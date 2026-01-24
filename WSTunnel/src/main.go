package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
)

// 1. 全局定义与工具
// ==========================================

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
)

type ConfigModel struct {
	Id          int64        `json:"id"`
	LeftDevice  string       `json:"leftDevice"`
	RightDevice string       `json:"rightDevice"`
	Lines       []LineConfig `json:"lines"`
}

type LineConfig struct {
	Id        string `json:"id"`
	Server    string `json:"server"`
	Client    string `json:"client"`
	ServerTls bool   `json:"serverTls"`
	ClientTls bool   `json:"clientTls"`
}

type ConfigManager struct {
	relayURL   string
	prefix     string
	myHostname string
	httpClient *http.Client
}

func NewConfigManager(relay, prefix, hostname string) *ConfigManager {
	return &ConfigManager{
		relayURL:   relay,
		prefix:     prefix,
		myHostname: hostname,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (cm *ConfigManager) Poll() ([]ConfigModel, error) {
	// Construct URL: {RelayURL}/{Prefix}/admin/config
	u, err := url.Parse(cm.relayURL)
	if err != nil {
		return nil, err
	}
	u.Path = path.Join(u.Path, cm.prefix, "admin", "config")
	q := u.Query()
	q.Set("hostname", cm.myHostname)
	u.RawQuery = q.Encode()

	// log.Printf("[Config] Polling %s", u.String())

	resp, err := cm.httpClient.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %s", resp.Status)
	}

	var allConfigs []ConfigModel
	if err := json.NewDecoder(resp.Body).Decode(&allConfigs); err != nil {
		return nil, err
	}

	return allConfigs, nil
}

type ServerSession struct {
	session   *yamux.Session
	nextToken string
	hostname  string // Store hostname for query purposes if needed, though we use knownDevices for the list
}

func randString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	for i, v := range b {
		b[i] = letters[v%byte(len(letters))]
	}
	return string(b)
}

func hostnameMatches(configName, localName string) bool {
	if configName == localName {
		return true
	}
	// Try Base64 decode
	decodedBytes, err := base64.StdEncoding.DecodeString(configName)
	if err == nil && string(decodedBytes) == localName {
		return true
	}
	return false
}

// WSConn 适配器：将 websocket.Conn 包装成 net.Conn 接口
type WSConn struct {
	*websocket.Conn
	reader io.Reader
}

func (c *WSConn) Read(b []byte) (int, error) {
	for {
		if c.reader == nil {
			msgType, r, err := c.NextReader()
			if err != nil {
				return 0, err
			}
			if msgType != websocket.BinaryMessage {
				continue
			}
			c.reader = r
		}
		n, err := c.reader.Read(b)
		if err == io.EOF {
			c.reader = nil
			continue
		}
		return n, err
	}
}

func (c *WSConn) Write(b []byte) (int, error) {
	err := c.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *WSConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// buildURL 辅助函数：处理 ws/wss 前缀及路径拼接
func buildURL(input, prefix, role, hostname, id string) (string, error) {
	// Normalize scheme for WebSocket
	if strings.HasPrefix(input, "http://") {
		input = "ws://" + input[7:]
	} else if strings.HasPrefix(input, "https://") {
		input = "wss://" + input[8:]
	} else if !strings.Contains(input, "://") {
		input = "ws://" + input
	}

	u, err := url.Parse(input)
	if err != nil {
		return "", err
	}
	u.Path = path.Join(u.Path, prefix, role, url.PathEscape(hostname), id)
	return u.String(), nil
}

// createDialer 创建一个自定义的 WebSocket Dialer
// 核心逻辑：如果提供了 specificIP，则在 TCP 拨号阶段强制连接该 IP，
// 但上层的 TLS 握手仍然使用 URL 中的域名（保留 SNI）。
func createDialer(specificIP string) *websocket.Dialer {
	dialer := &websocket.Dialer{
		Proxy:            nil,
		HandshakeTimeout: 10 * time.Second,
	}

	// 如果指定了特定 IP，劫持底层网络拨号
	if specificIP != "" {
		dialer.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			// addr 原始格式为 "example.com:443"
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			// 重组为 "1.2.3.4:443"
			targetAddr := net.JoinHostPort(specificIP, port)

			log.Printf("[Dialer] Redirecting connection: %s -> %s (SNI preserved)", addr, targetAddr)

			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, network, targetAddr)
		}

		// 显式设置 TLSClientConfig 以确保 InsecureSkipVerify 等参数可控（如果需要）
		// 注意：ServerName 会由 websocket 库自动根据 Dial 的 URL 填充，这里不需要手动覆盖 ServerName
		dialer.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	} else {
		// Only set InsecureSkipVerify if user wants global insecurity?
		// Actually, for normal Relay without --relay-ip, we might still want it if using self-signed certs.
		// But let's stick to default behavior or enable it if scheme is wss and no trusted cert.
		// For now, let's just ensure we have a TLS config if we need it.
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return dialer
}

// ==========================================
// 2. Relay 端 (公网中转)
// ==========================================

type Relay struct {
	addr         string
	prefix       string
	staticPath   string
	servers      sync.Map // map[id]ServerSession
	knownDevices sync.Map // map[hostname]bool (using hostname as key, or maybe just storing a list? Requirement says "return a list containing all url encoded hostname")
	// The requirement: "2：devices：返回一个列表，包含所有url编码过的hostname"
	// "无论是否在线" -> means we accumulate them.
	// Since we need to return a list of hostnames, a set (map[string]bool) is appropriate to avoid duplicates.

	config     []ConfigModel
	configLock sync.RWMutex
}

func (r *Relay) Start() {
	serverPath := path.Join("/", r.prefix, "server") + "/"
	clientPath := path.Join("/", r.prefix, "client") + "/"

	// Admin routes
	adminStaticPath := path.Join("/", r.prefix, "admin", "static")
	adminDevicesPath := path.Join("/", r.prefix, "admin", "devices")
	adminConfigPath := path.Join("/", r.prefix, "admin", "config")

	http.HandleFunc(serverPath, r.handleServerReg)
	http.HandleFunc(clientPath, r.handleClientConn)

	http.HandleFunc(adminStaticPath, r.handleAdminStatic)
	http.HandleFunc(adminDevicesPath, r.handleAdminDevices)
	http.HandleFunc(adminConfigPath, r.handleAdminConfig)

	log.Printf("[Relay] Listening on %s, Prefix: %s", r.addr, r.prefix)
	log.Printf("[Relay] Admin Static: %s -> %s", adminStaticPath, r.staticPath)

	if err := http.ListenAndServe(r.addr, nil); err != nil {
		log.Fatal(err)
	}
}

func (r *Relay) handleAdminStatic(w http.ResponseWriter, req *http.Request) {
	if r.staticPath == "" {
		http.Error(w, "Static path not configured", http.StatusNotFound)
		return
	}
	http.ServeFile(w, req, r.staticPath)
}

func (r *Relay) handleAdminDevices(w http.ResponseWriter, req *http.Request) {
	var devices []string
	r.knownDevices.Range(func(key, value interface{}) bool {
		if hostname, ok := key.(string); ok {
			devices = append(devices, hostname)
		}
		return true
	})

	// Return JSON list
	w.Header().Set("Content-Type", "application/json")
	// Manually marshal to avoid importing encoding/json if not already (it's not).
	// But ConfigModel needs json anyway.
	// Wait, I need to check imports. "encoding/json" is NOT imported in the original file. I must add it.
	// Actually, I'll use fmt.Fprintf for simple list if I can't import, but `ConfigModel` requires `json` package struct tags so I should add the import.
	// I will address imports in a separate edit or let auto-import handle it if I was using an IDE, but here I must be explicit.
	// I'll proceed assuming I will add "encoding/json" to imports.

	// Quick manual json generation for list of strings is easy:
	// ["a","b"]

	w.Write([]byte("["))
	for i, d := range devices {
		if i > 0 {
			w.Write([]byte(","))
		}
		fmt.Fprintf(w, "\"%s\"", d)
	}
	w.Write([]byte("]"))
}

func (r *Relay) handleAdminConfig(w http.ResponseWriter, req *http.Request) {
	// Register device if query param present
	if h := req.URL.Query().Get("hostname"); h != "" {
		// handleServerReg uses req.URL.Path which is decoded.
		// So we must store the decoded hostname to avoid duplicates (e.g. "Test A" vs "Test%20A").
		r.knownDevices.Store(h, true)
	}

	w.Header().Set("Content-Type", "application/json")
	if req.Method == http.MethodGet {
		r.configLock.RLock()
		defer r.configLock.RUnlock()
		if r.config == nil {
			w.Write([]byte("[]"))
			return
		}
		json.NewEncoder(w).Encode(r.config)
		return
	}

	if req.Method == http.MethodPost {
		var newConfig []ConfigModel
		if err := json.NewDecoder(req.Body).Decode(&newConfig); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		r.configLock.Lock()
		r.config = newConfig
		r.configLock.Unlock()

		json.NewEncoder(w).Encode(newConfig)
	}
}

func (r *Relay) handleServerReg(w http.ResponseWriter, req *http.Request) {
	// Path format: /{prefix}/server/{hostname}/{id}/{past}/{next}
	trimmedPath := strings.Trim(req.URL.Path, "/")
	parts := strings.Split(trimmedPath, "/")
	// Expected parts: prefix, "server", hostname, id, past, next
	if len(parts) < 6 {
		http.Error(w, "Invalid path format (need /{prefix}/server/{hostname}/{id}/{past}/{next})", http.StatusBadRequest)
		return
	}
	hostnameRaw, id, past, next := parts[2], parts[3], parts[4], parts[5]
	// hostnameRaw is URL encoded. We are asked to return a list of "url encoded hostname".
	// So we should store hostnameRaw as is?
	// User said: "devices：返回一个列表，包含所有url编码过的hostname" (return a list containing all url encoded hostname)
	// So yes, we store it as is.
	// Wait, in buildURL we do url.PathEscape(hostname).
	// Here we get it from path.
	// If I store `hostnameRaw`, it is already encoded (e.g. "foo%20bar").
	// Let's store `hostnameRaw`.

	r.knownDevices.Store(hostnameRaw, true) // Register device

	hostname, _ := url.PathUnescape(hostnameRaw)

	if val, ok := r.servers.Load(id); ok {
		oldSessWrapper := val.(ServerSession)
		if oldSessWrapper.nextToken != past {
			log.Printf("[Relay] Token mismatch for %s. Expected %s, got %s", id, oldSessWrapper.nextToken, past)
			http.Error(w, "Token mismatch", http.StatusUnauthorized)
			return
		}
	}

	ws, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		return
	}

	// 2nd check after upgrade (to close old session)
	if val, ok := r.servers.Load(id); ok {
		oldSessWrapper := val.(ServerSession)
		// We already checked token above, but race condition possible?
		// Ideally we lock, but sync.Map doesn't lock.
		// Double check to be safe or just proceed.
		// If token changed between checks, it means another connection succeeded?
		if oldSessWrapper.nextToken == past {
			log.Printf("[Relay] Reconnection accepted for %s. Closing old session.", id)
			oldSessWrapper.session.Close()
		}
	}

	conn := &WSConn{Conn: ws}

	ymConfig := yamux.DefaultConfig()
	// 关键：关闭 Yamux 自带的心跳，防止因网络波动或 WS 延迟导致的误判
	ymConfig.EnableKeepAlive = false
	// 可选：如果希望保持心跳但放宽限制，可以保留 true 并增加时长，例如：
	// ymConfig.KeepAliveInterval = 30 * time.Second
	// ymConfig.ConnectionWriteTimeout = 15 * time.Second

	// 使用配置创建 Session
	session, err := yamux.Client(conn, ymConfig)
	if err != nil {
		ws.Close()
		return
	}

	r.servers.Store(id, ServerSession{session: session, nextToken: next, hostname: hostname})
	log.Printf("[Relay] Server registered: %s (Host: %s)", id, hostname)

	<-session.CloseChan()

	if val, ok := r.servers.Load(id); ok && val.(ServerSession).session == session {
		r.servers.Delete(id)
		log.Printf("[Relay] Server disconnected: %s", id)
	}
}

func (r *Relay) handleClientConn(w http.ResponseWriter, req *http.Request) {
	// Path format: /{prefix}/client/{hostname}/{id}
	trimmedPath := strings.Trim(req.URL.Path, "/")
	parts := strings.Split(trimmedPath, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid path format", http.StatusBadRequest)
		return
	}
	hostname, id := parts[2], parts[3]
	hostname, _ = url.PathUnescape(hostname)

	val, ok := r.servers.Load(id)
	if !ok {
		http.Error(w, "Service ID offline", http.StatusNotFound)
		return
	}
	session := val.(ServerSession).session

	ws, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	stream, err := session.Open()
	if err != nil {
		log.Printf("[Relay] Stream open failed: %v", err)
		return
	}
	defer stream.Close()

	wsWrapper := &WSConn{Conn: ws}
	log.Printf("[Relay] Client connecting to %s (Host: %s)", id, hostname)
	join(wsWrapper, stream)
}

// ==========================================
// 3. Server 端 (S端)
// ==========================================

type Server struct {
	relayAddr string
	relayIP   string
	prefix    string
	hostname  string // matches LeftDevice
	cm        *ConfigManager

	mu       sync.Mutex
	sessions map[string]*ServerJob // Key: Line ID
}

type ServerJob struct {
	config LineConfig
	cancel context.CancelFunc
	done   chan struct{}
}

func (s *Server) Update(configs []ConfigModel) {

	// Find my config
	var myLines []LineConfig
	found := false
	for _, cfg := range configs {
		if hostnameMatches(cfg.LeftDevice, s.hostname) {
			myLines = cfg.Lines
			found = true
			break
		}
	}

	if !found {
		// Log rarely to avoid spam, or verify against last state?
		// For now, let's log if we previously had lines or just once in a while.
		// Or just log "No config found for hostname X"
		// log.Printf("[Server] No config found for hostname: %s", s.hostname)
		myLines = []LineConfig{}
	} else {
		log.Printf("[Server] Config found: %d lines for %s", len(myLines), s.hostname)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions == nil {
		s.sessions = make(map[string]*ServerJob)
	}

	// Map new configs for easy lookup
	newMap := make(map[string]LineConfig)
	for _, l := range myLines {
		newMap[l.Id] = l
	}

	// 1. Identify removals and changes
	for id, job := range s.sessions {
		newCfg, exists := newMap[id]
		if !exists || newCfg != job.config {
			// Stop existing job
			log.Printf("[Server] Stopping line %s (Changed/Removed)", id)
			job.cancel()
			<-job.done // Wait for cleanup
			delete(s.sessions, id)
		}
	}

	// 2. Identify additions
	for id, cfg := range newMap {
		if _, exists := s.sessions[id]; !exists {
			log.Printf("[Server] Starting line %s: %s -> Relay", id, cfg.Server)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})

			job := &ServerJob{
				config: cfg,
				cancel: cancel,
				done:   done,
			}
			s.sessions[id] = job

			go s.runLine(ctx, cfg, done)
		}
	}
}

func (s *Server) runLine(ctx context.Context, cfg LineConfig, done chan struct{}) {
	defer close(done)
	dialer := createDialer(s.relayIP)

	// Inner loop for reconnection
	var next string
	lastNext := "init"

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if next == "" {
			next = randString(16)
		}

		// URL: /{prefix}/server/{hostname}/{lineId}/{past}/{next}
		// Note: The previous logic used serviceID as the 'id' in URL. Now we use line.Id.
		targetURL, err := buildURL(s.relayAddr, s.prefix, "server", s.hostname, cfg.Id+"/"+lastNext+"/"+next)
		if err != nil {
			log.Printf("[Server] %s URL build error: %v", cfg.Id, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
				continue
			}
		}

		success := s.connectAndServe(ctx, dialer, targetURL, cfg.Server)
		if success {
			lastNext = next
			next = ""
		} else {
			// Keep tokens, retry
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
}

func (s *Server) connectAndServe(ctx context.Context, dialer *websocket.Dialer, targetURL, localTarget string) bool {
	ws, _, err := dialer.Dial(targetURL, nil)
	if err != nil {
		log.Printf("[Server] Relay dial failed (target: %s, relay: %s): %v", localTarget, targetURL, err)
		return false
	}

	conn := &WSConn{Conn: ws}
	ymConfig := yamux.DefaultConfig()
	ymConfig.EnableKeepAlive = false

	session, err := yamux.Server(conn, ymConfig)
	if err != nil {
		ws.Close()
		return false
	}
	defer session.Close()

	// Watch for context cancellation to close session
	go func() {
		<-ctx.Done()
		session.Close()
	}()

	for {
		stream, err := session.Accept()
		if err != nil {
			return true // Session broken, but was successful
		}

		go func(remoteStream net.Conn) {
			defer remoteStream.Close()
			localConn, err := net.Dial("tcp", localTarget)
			if err != nil {
				log.Printf("[Server] Failed to dial local %s: %v", localTarget, err)
				return
			}
			defer localConn.Close()
			join(localConn, remoteStream)
		}(stream)
	}
}

// ==========================================
// 4. Client 端 (C端)
// ==========================================

type Client struct {
	relayAddr string
	relayIP   string
	prefix    string
	hostname  string // matches RightDevice
	cm        *ConfigManager

	mu        sync.Mutex
	listeners map[string]*ClientJob // Key: Line ID
}

type ClientJob struct {
	config   LineConfig
	listener net.Listener
}

func (c *Client) Update(configs []ConfigModel) {

	var myLines []LineConfig
	found := false
	for _, cfg := range configs {
		if hostnameMatches(cfg.RightDevice, c.hostname) {
			myLines = cfg.Lines
			found = true
			break
		}
	}

	if !found {
		myLines = []LineConfig{}
	} else {
		log.Printf("[Client] Config found: %d lines for %s", len(myLines), c.hostname)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.listeners == nil {
		c.listeners = make(map[string]*ClientJob)
	}

	newMap := make(map[string]LineConfig)
	for _, l := range myLines {
		newMap[l.Id] = l
	}

	// 1. Remove/Change
	for id, job := range c.listeners {
		newCfg, exists := newMap[id]
		if !exists || newCfg != job.config {
			log.Printf("[Client] Stopping line %s (Changed/Removed)", id)
			job.listener.Close()
			delete(c.listeners, id)
		}
	}

	// 2. Add
	for id, cfg := range newMap {
		if _, exists := c.listeners[id]; !exists {
			log.Printf("[Client] Starting line %s: %s -> Relay", id, cfg.Client)
			ln, err := net.Listen("tcp", cfg.Client)
			if err != nil {
				log.Printf("[Client] Listen failed on %s: %v", cfg.Client, err)
				continue
			}

			job := &ClientJob{
				config:   cfg,
				listener: ln,
			}
			c.listeners[id] = job

			go c.runListener(ln, cfg)
		}
	}
}

func (c *Client) runListener(ln net.Listener, cfg LineConfig) {
	// Need to build target URL with line ID
	// URL: /{prefix}/client/{hostname}/{lineId}

	dialer := createDialer(c.relayIP)

	// We build targetURL once, but relay might change?
	// Actually, client just connects to relay for tunnel.
	// The session ID on relay is the line ID.
	targetURL, err := buildURL(c.relayAddr, c.prefix, "client", c.hostname, cfg.Id)
	if err != nil {
		log.Printf("[Client] URL build error: %v", err)
		ln.Close() // Should we close listener? Yes, fatal for this line.
		return
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			// Listener closed or error
			return
		}

		go func(userConn net.Conn) {
			defer userConn.Close()

			ws, _, err := dialer.Dial(targetURL, nil)
			if err != nil {
				log.Printf("[Client] Relay dial failed: %v", err)
				return
			}
			defer ws.Close()

			wsWrapper := &WSConn{Conn: ws}
			join(userConn, wsWrapper)
		}(conn)
	}
}

func (s *Server) getDisplayIP() string {
	if s.relayIP == "" {
		return "Auto/DNS"
	}
	return s.relayIP
}

func (c *Client) getDisplayIP() string {
	if c.relayIP == "" {
		return "Auto/DNS"
	}
	return c.relayIP
}

func join(c1, c2 io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(c1, c2); c1.Close() }()
	go func() { defer wg.Done(); io.Copy(c2, c1); c2.Close() }()
	wg.Wait()
}

// ==========================================
// 6. Main 入口
// ==========================================

func main() {
	// 基础参数
	mode := flag.String("mode", "", "Run mode: [relay | edge]")

	// 网络参数
	port := flag.String("port", ":8080", "[Relay] Listen port")
	relayAddr := flag.String("relay", "wss://example.com", "[Client/Server] Relay address (URL)")
	relayIP := flag.String("relay-ip", "", "[Client/Server] Force connection to specific IP (Keep SNI)")

	// 转发参数
	prefix := flag.String("prefix", "123456", "Path prefix for server and client")
	hostname := flag.String("hostname", "", "Hostname for server/client (defaults to OS hostname)")

	// Admin参数
	adminStatic := flag.String("admin-static", "", "[Relay] Path to static HTML file for admin interface")

	flag.Parse()

	// Handle default hostname
	if *hostname == "" {
		host, err := os.Hostname()
		if err == nil {
			*hostname = host
		} else {
			*hostname = "unknown"
		}
	}

	switch *mode {
	case "relay":
		r := &Relay{
			addr:       *port,
			prefix:     *prefix,
			staticPath: *adminStatic,
		}
		r.Start()

	case "edge":
		if *relayAddr == "" {
			log.Fatal("Error: -relay is required for edge mode")
		}
		if *hostname == "" {
			log.Fatal("Error: -hostname is required for edge mode (or use system hostname)")
		}

		cm := NewConfigManager(*relayAddr, *prefix, *hostname)
		s := &Server{
			relayAddr: *relayAddr,
			relayIP:   *relayIP,
			prefix:    *prefix,
			hostname:  *hostname,
			cm:        cm,
		}
		c := &Client{
			relayAddr: *relayAddr,
			relayIP:   *relayIP,
			prefix:    *prefix,
			hostname:  *hostname,
			cm:        cm,
		}

		log.Printf("[Edge] Starting with hostname: %s. Polling relay %s", *hostname, *relayAddr)

		poll := func() {
			configs, err := cm.Poll()
			if err != nil {
				log.Printf("[Edge] Config poll failed: %v", err)
				return
			}
			s.Update(configs)
			c.Update(configs)
		}

		ticker := time.NewTicker(time.Second * 30)
		defer ticker.Stop()

		poll()
		for range ticker.C {
			poll()
		}

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: wsTunnel -mode [mode] [options]")
	fmt.Println("\nModes:")
	fmt.Println("  relay   Run as the public relay server")

	fmt.Println("\nOptions:")
	flag.PrintDefaults()
	fmt.Println("\nExamples:")
	fmt.Println("  Relay:  wsTunnel -mode relay -port :8080")
	fmt.Println("  Edge:   wsTunnel -mode edge -relay http://127.0.0.1:8787 -hostname my-device")
}
