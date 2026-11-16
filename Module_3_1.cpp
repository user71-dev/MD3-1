#include <Windows.h>
#include <stdio.h>
#include <string>
#include <iostream>

#include "DllInjection.h"
#include "SetWindowsHookEx.h"

int wmain(int argc, wchar_t* argv[])
{
    SetConsoleOutputCP(CP_UTF8);

    // Sửa thành argc < 3 vì kỹ thuật pe không cần đường dẫn file
    if (argc < 3) {
        fprintf(stderr, "Usage: %ls <technique> <pid> [file_path]\n", argv[0]);
        fprintf(stderr, "  Ex:  %ls dll 1234 C:\\lab\\payload.dll\n", argv[0]);
        fprintf(stderr, "  Ex:  %ls pe  5678\n", argv[0]);
        return 1;
    }

    std::wstring technique = argv[1];

    // --- Parse PID (argv[2]) ---
    wchar_t* end = nullptr;
    unsigned long pidUl = wcstoul(argv[2], &end, 10);
    if (*end != L'\0' || pidUl == 0 || pidUl > 0xFFFFFFFFUL) {
        fprintf(stderr, "[ERR] Invalid PID: %ls\n", argv[2]);
        return 1;
    }
    const DWORD pid = static_cast<DWORD>(pidUl);

    std::wstring fullPath = L"";
    BOOL success = FALSE;

    if (technique == L"dll" || technique == L"hook") {
        if (argc != 4) {
            fprintf(stderr, "[ERR] Thieu file_path.\n");
            return 1;
        }
        wchar_t buffer[MAX_PATH];
        if (!GetFullPathNameW(argv[3], MAX_PATH, buffer, nullptr)) {
            PrintLastError("GetFullPathNameW");
            return 1;
        }
        if (GetFileAttributesW(buffer) == INVALID_FILE_ATTRIBUTES) {
            fprintf(stderr, "[ERR] File not found: %ls\n", buffer);
            return 1;
        }
        fullPath = buffer;

        printf("[*] Technique  : %ls\n", technique.c_str());
        printf("[*] Target PID : %lu\n", pid);
        printf("[*] Payload    : %ls\n", fullPath.c_str());
        printf("[*] Injecting...\n\n");
    }

    if (technique == L"dll") {
        printf("[*] Using DLL Injection technique...\n");
        success = InjectDll(pid, fullPath.c_str());
    }
    else if (technique == L"hook") {
        printf("[*] Using SetWindowsHookEx technique...\n");
        success = InjectDllViaSetWindowsHookEx(pid, fullPath.c_str());
    }
    else {
        fprintf(stderr, "[ERR] Unknown technique: %ls\n", technique.c_str());
        return 1;
    }
    
    if (!success) {
        printf("\n[!] Injection FAILED.\n");
        return 1;
    }

    if (technique == L"hook") {
        // Chỉ kỹ thuật hook mới cần giữ injector sống để hook tồn tại
        printf("\n[*] Hook da cai. Nhan Enter de go hook va thoat...\n");
        getchar();
        printf("[*] Da go hook.\n");
    }
    else {
        // Kỹ thuật dll: DLL đã được nạp vào tiến trình đích,
        // injector có thể thoát ngay, không cần giữ sống.
        printf("\n[*] Done.\n");
    }

    return 0;
}
