#include "SetWindowsHookEx.h"
#include <stdio.h>

// Hàm phụ: Tìm Thread ID của cửa sổ chính thuộc PID
DWORD GetMainThreadId(DWORD pid) {
    DWORD threadId = 0;
    HWND hWnd = FindWindow(NULL, NULL); // Bắt đầu tìm
    do {
        DWORD wndPid = 0;
        DWORD tid = GetWindowThreadProcessId(hWnd, &wndPid);
        if (wndPid == pid && IsWindowVisible(hWnd) && GetWindow(hWnd, GW_OWNER) == NULL) {
            threadId = tid;
            break;
        }
        hWnd = GetWindow(hWnd, GW_HWNDNEXT);
    } while (hWnd != NULL);
    return threadId;
}

bool InjectDllViaSetWindowsHookEx(DWORD targetPid, const wchar_t* dllPath) {
    // 1. Tìm thread của cửa sổ chính (chính xác hơn hàm FindThreadByProcessId cũ)
    DWORD targetThreadId = GetMainThreadId(targetPid);
    if (targetThreadId == 0) {
        printf("[-] Khong tim thay Main Thread cua PID %lu\n", targetPid);
        return false;
    }
    printf("[+] Thread dich (Main UI): %lu\n", targetThreadId);

    // 2. Load DLL
    g_hDll = LoadLibraryW(dllPath);
    if (!g_hDll) {
        printf("[-] LoadLibrary that bai: %lu\n", GetLastError());
        return false;
    }

    // 3. Lấy địa chỉ hàm export
    HOOKPROC hookProc = (HOOKPROC)GetProcAddress(g_hDll, "spotlessExport");
    if (!hookProc) {
        printf("[-] GetProcAddress that bai: %lu\n", GetLastError());
        FreeLibrary(g_hDll); g_hDll = NULL;
        return false;
    }

    // 4. Cài hook WH_KEYBOARD lên thread đích
    g_hHook = SetWindowsHookExA(WH_GETMESSAGE, hookProc, g_hDll, targetThreadId);
    if (!g_hHook) {
        printf("[-] SetWindowsHookEx that bai: %lu\n", GetLastError());
        FreeLibrary(g_hDll); g_hDll = NULL;
        return false;
    }
    printf("[+] Da cai hook: 0x%p\n", g_hHook);

    return true;
}