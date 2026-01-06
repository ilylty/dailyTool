/*
 * 项目名称: EdgeFlow
 * 功能描述: 鼠标悬停屏幕边缘自动切换 Windows 虚拟桌面
 * 编译环境: Visual Studio (MSVC)
 */

#include <windows.h>
#include <string>
#include <chrono>
#include <thread>
#include <vector>

// 强制配置链接器参数：设置为窗口子系统（隐藏控制台黑框）
#pragma comment(linker, "/SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup")

// 状态枚举
enum EdgeState {
    NONE,
    LEFT_EDGE,
    RIGHT_EDGE,
    TOP_LEFT_CORNER // 用于安全退出
};

// 模拟 Ctrl + Win + Left/Right
void SendDesktopSwitch(bool next) {
    WORD keyDirection = next ? VK_RIGHT : VK_LEFT;
    INPUT inputs[6] = {};

    // 1. Win Down, 2. Ctrl Down
    inputs[0].type = inputs[1].type = INPUT_KEYBOARD;
    inputs[0].ki.wVk = VK_LWIN;
    inputs[1].ki.wVk = VK_CONTROL;

    // 3. Arrow Down
    inputs[2].type = INPUT_KEYBOARD;
    inputs[2].ki.wVk = keyDirection;

    // 4. Arrow Up
    inputs[3].type = INPUT_KEYBOARD;
    inputs[3].ki.wVk = keyDirection;
    inputs[3].ki.dwFlags = KEYEVENTF_KEYUP;

    // 5. Ctrl Up, 6. Win Up
    inputs[4].type = inputs[5].type = INPUT_KEYBOARD;
    inputs[4].ki.wVk = VK_CONTROL;
    inputs[4].ki.dwFlags = KEYEVENTF_KEYUP;
    inputs[5].ki.wVk = VK_LWIN;
    inputs[5].ki.dwFlags = KEYEVENTF_KEYUP;

    SendInput(6, inputs, sizeof(INPUT));
}

// Windows GUI 程序入口
int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR    lpCmdLine,
    _In_ int       nCmdShow)
{
    // --- 1. 单例检查 (防止重复开启) ---
    HANDLE hMutex = CreateMutex(NULL, TRUE, L"Global\\EdgeFlowMutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBox(NULL, L"EdgeFlow 已经在运行中！", L"提示", MB_OK | MB_ICONINFORMATION);
        return 0; 
    }

    // --- 2. 参数解析 (延迟时间) ---
    int triggerDelayMs = 300; // 默认延迟 300ms
    if (lpCmdLine && wcslen(lpCmdLine) > 0) {
        try {
            triggerDelayMs = std::stoi(lpCmdLine);
        } catch (...) {}
    }
    if (triggerDelayMs < 100) triggerDelayMs = 100; // 最小限制

    // --- 3. 状态初始化 ---
    EdgeState currentEdge = NONE;
    auto hoverStartTime = std::chrono::steady_clock::now();
    bool isTriggered = false;

    // 退出检测计时器
    auto exitStartTime = std::chrono::steady_clock::now();
    bool checkingExit = false;

    // --- 4. 主循环 ---
    while (true) {
        POINT p;
        if (GetCursorPos(&p)) {
            // 获取虚拟屏幕边界 (支持多显示器拼接)
            int vScreenLeft = GetSystemMetrics(SM_XVIRTUALSCREEN);
            int vScreenTop = GetSystemMetrics(SM_YVIRTUALSCREEN);
            int vScreenWidth = GetSystemMetrics(SM_CXVIRTUALSCREEN);
            int vScreenRight = vScreenLeft + vScreenWidth - 1;

            EdgeState detectedEdge = NONE;

            // 判定区域
            if (p.x <= vScreenLeft && p.y <= vScreenTop) {
                detectedEdge = TOP_LEFT_CORNER; // 左上角死角
            } else if (p.x <= vScreenLeft) {
                detectedEdge = LEFT_EDGE;
            } else if (p.x >= vScreenRight) {
                detectedEdge = RIGHT_EDGE;
            }

            // A. 安全退出逻辑 (左上角停留 3 秒)
            if (detectedEdge == TOP_LEFT_CORNER) {
                if (!checkingExit) {
                    checkingExit = true;
                    exitStartTime = std::chrono::steady_clock::now();
                } else {
                    auto now = std::chrono::steady_clock::now();
                    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - exitStartTime).count() > 3000) {
                        if (MessageBox(NULL, L"确定要退出 EdgeFlow 吗？", L"退出", MB_YESNO | MB_ICONQUESTION) == IDYES) {
                            break; // 退出循环
                        }
                        // 如果点No，重置状态防止连续弹窗
                        checkingExit = false;
                        currentEdge = NONE; 
                    }
                }
            } else {
                checkingExit = false;
            }

            // B. 切换桌面逻辑
            if (detectedEdge == LEFT_EDGE || detectedEdge == RIGHT_EDGE) {
                if (currentEdge != detectedEdge) {
                    // 刚进入边缘
                    currentEdge = detectedEdge;
                    hoverStartTime = std::chrono::steady_clock::now();
                    isTriggered = false;
                } else {
                    // 停留在边缘
                    if (!isTriggered) {
                        auto now = std::chrono::steady_clock::now();
                        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - hoverStartTime).count() >= triggerDelayMs) {
                            // 执行切换
                            SendDesktopSwitch(detectedEdge == RIGHT_EDGE);
                            isTriggered = true; // 锁定，直到移开
                        }
                    }
                }
            } else {
                // 移出边缘 (不包括 TopLeftCorner)
                if (detectedEdge != TOP_LEFT_CORNER) {
                    currentEdge = NONE;
                    isTriggered = false;
                }
            }
        }
        // 低功耗休眠
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    if (hMutex) {
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
    }
    return 0;
}