package main

import (
	"context"
	"crypto/tls"
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

// ==========================================
// 1. 全局定义与工具
// ==========================================

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
)

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
func buildURL(input, role, id string) (string, error) {
	if !strings.Contains(input, "://") {
		input = "ws://" + input
	}
	u, err := url.Parse(input)
	if err != nil {
		return "", err
	}
	u.Path = path.Join(u.Path, role, id)
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
	}

	return dialer
}

// ==========================================
// 2. Relay 端 (公网中转)
// ==========================================

type Relay struct {
	addr    string
	servers sync.Map
}

func (r *Relay) Start() {
	http.HandleFunc("/server/", r.handleServerReg)
	http.HandleFunc("/client/", r.handleClientConn)

	log.Printf("[Relay] Listening on %s", r.addr)
	if err := http.ListenAndServe(r.addr, nil); err != nil {
		log.Fatal(err)
	}
}

func (r *Relay) handleServerReg(w http.ResponseWriter, req *http.Request) {
	id := path.Base(req.URL.Path)
	if id == "" || id == "/" {
		http.Error(w, "Missing Service ID", http.StatusBadRequest)
		return
	}

	ws, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		return
	}

	if _, ok := r.servers.Load(id); ok {
		ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "ID collision"))
		ws.Close()
		return
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

	r.servers.Store(id, session)
	log.Printf("[Relay] Server registered: %s", id)

	<-session.CloseChan()

	if val, ok := r.servers.Load(id); ok && val == session {
		r.servers.Delete(id)
		log.Printf("[Relay] Server disconnected: %s", id)
	}
}

func (r *Relay) handleClientConn(w http.ResponseWriter, req *http.Request) {
	id := path.Base(req.URL.Path)
	val, ok := r.servers.Load(id)
	if !ok {
		http.Error(w, "Service ID offline", http.StatusNotFound)
		return
	}
	session := val.(*yamux.Session)

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
	join(wsWrapper, stream)
}

// ==========================================
// 3. Server 端 (S端)
// ==========================================

type Server struct {
	relayAddr   string
	relayIP     string // 强制指定的 IP
	serviceID   string
	localTarget string
}

func (s *Server) Start() {
	targetURL, err := buildURL(s.relayAddr, "server", s.serviceID)
	if err != nil {
		log.Fatalf("[Server] Invalid relay address: %v", err)
	}

	log.Printf("[Server] Target: %s (Physical IP: %s)", targetURL, s.getDisplayIP())
	dialer := createDialer(s.relayIP)

	for {
		s.connectAndServe(dialer, targetURL)
		log.Println("[Server] Reconnecting in 3s...")
		time.Sleep(3 * time.Second)
	}
}

func (s *Server) getDisplayIP() string {
	if s.relayIP == "" {
		return "Auto/DNS"
	}
	return s.relayIP
}

func (s *Server) connectAndServe(dialer *websocket.Dialer, targetURL string) {
	// 使用自定义 dialer 进行连接
	ws, _, err := dialer.Dial(targetURL, nil)
	if err != nil {
		log.Printf("[Server] Dial error: %v", err)
		return
	}

	conn := &WSConn{Conn: ws}
	ymConfig := yamux.DefaultConfig()
	// 关键：关闭 Yamux 自带的心跳，防止因网络波动或 WS 延迟导致的误判
	ymConfig.EnableKeepAlive = false
	// 可选：如果希望保持心跳但放宽限制，可以保留 true 并增加时长，例如：
	// ymConfig.KeepAliveInterval = 30 * time.Second
	// ymConfig.ConnectionWriteTimeout = 15 * time.Second

	// 使用配置创建 Session
	session, err := yamux.Server(conn, ymConfig)
	if err != nil {
		ws.Close()
		log.Printf("[Server] Session error: %v", err)
		return
	}
	defer session.Close()

	log.Printf("[Server] Online as '%s'", s.serviceID)

	for {
		stream, err := session.Accept()
		if err != nil {
			return
		}

		go func(remoteStream net.Conn) {
			defer remoteStream.Close()
			localConn, err := net.Dial("tcp", s.localTarget)
			if err != nil {
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
	relayAddr   string
	relayIP     string // 强制指定的 IP
	serviceID   string
	localListen string
	dialer      *websocket.Dialer
	targetURL   string
}

func (c *Client) Start() {
	var err error
	c.targetURL, err = buildURL(c.relayAddr, "client", c.serviceID)
	if err != nil {
		log.Fatalf("[Client] Invalid relay URL: %v", err)
	}

	// 预先创建 Dialer，避免每次连接重复创建
	c.dialer = createDialer(c.relayIP)

	listener, err := net.Listen("tcp", c.localListen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("[Client] Listening %s -> %s (Via %s, IP: %s)",
		c.localListen, c.serviceID, c.relayAddr, c.getDisplayIP())

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go c.handleConn(conn)
	}
}

func (c *Client) getDisplayIP() string {
	if c.relayIP == "" {
		return "Auto/DNS"
	}
	return c.relayIP
}

func (c *Client) handleConn(userConn net.Conn) {
	defer userConn.Close()

	ws, _, err := c.dialer.Dial(c.targetURL, nil)
	if err != nil {
		log.Printf("[Client] Relay dial failed: %v", err)
		return
	}
	defer ws.Close()

	wsWrapper := &WSConn{Conn: ws}
	join(userConn, wsWrapper)
}

// ==========================================
// 5. 通用辅助函数
// ==========================================

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
	mode := flag.String("mode", "", "Run mode: [relay | server | client]")
	id := flag.String("id", "", "Service ID (Required for client/server)")

	// 网络参数
	port := flag.String("port", ":8080", "[Relay] Listen port")
	relayAddr := flag.String("relay", "wss://example.com", "[Client/Server] Relay address (URL)")
	relayIP := flag.String("relay-ip", "", "[Client/Server] Force connection to specific IP (Keep SNI)")

	// 转发参数
	target := flag.String("target", "127.0.0.1:22", "[Server] Target address to expose")
	listen := flag.String("listen", ":1080", "[Client] Local listening address")

	flag.Parse()

	switch *mode {
	case "relay":
		r := &Relay{addr: *port}
		r.Start()
	case "server":
		if *id == "" {
			log.Fatal("Error: -id is required for server mode")
		}
		s := &Server{
			relayAddr:   *relayAddr,
			relayIP:     *relayIP,
			serviceID:   *id,
			localTarget: *target,
		}
		s.Start()
	case "client":
		if *id == "" {
			log.Fatal("Error: -id is required for client mode")
		}
		c := &Client{
			relayAddr:   *relayAddr,
			relayIP:     *relayIP,
			serviceID:   *id,
			localListen: *listen,
		}
		c.Start()
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: wsTunnel -mode [mode] [options]")
	fmt.Println("\nModes:")
	fmt.Println("  relay   Run as the public relay server")
	fmt.Println("  server  Run as the service provider (exposes local port)")
	fmt.Println("  client  Run as the service consumer (listens on local port)")
	fmt.Println("\nOptions:")
	flag.PrintDefaults()
	fmt.Println("\nExamples:")
	fmt.Println("  Relay:  wsTunnel -mode relay -port :8080")
	fmt.Println("  Server: wsTunnel -mode server -relay wss://relay.com -id ssh -target 127.0.0.1:22 -relay-ip 1.2.3.4")
	fmt.Println("  Client: wsTunnel -mode client -relay wss://relay.com -id ssh -listen :2222 -relay-ip 1.2.3.4")
}
