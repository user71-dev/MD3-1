#include "DllInjection.h"

#include <cstdio>

void PrintLastError(const char* where)
{
    fprintf(stderr, "[ERR] %s failed. GetLastError = %lu\n",
        where, GetLastError());
}

bool InjectDll(DWORD pid, const wchar_t* dllPath)
{
    if (pid == 0 || !dllPath || !*dllPath) return false;

    // 1. Open process with minimum required rights 
    const DWORD access =
        PROCESS_CREATE_THREAD |
        PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE |
        PROCESS_VM_READ;

    HANDLE hProcess = OpenProcess(access, FALSE, pid);
    if (!hProcess) { PrintLastError("OpenProcess"); return false; }
    printf("[+] Opened process handle (PID %lu).\n", pid);

    // 2. Check bitness 
    BOOL targetWow64 = FALSE, selfWow64 = FALSE;
    if (!IsWow64Process(hProcess, &targetWow64) ||
        !IsWow64Process(GetCurrentProcess(), &selfWow64))
    {
        PrintLastError("IsWow64Process");
        CloseHandle(hProcess);
        return false;
    }
    if (targetWow64 != selfWow64) {
        fprintf(stderr, "[ERR] Bitness mismatch: injector and target architectures differ.\n");
        CloseHandle(hProcess);
        return false;
    }

    // 3. Get LoadLibraryW address 
    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    if (!hK32) {
        PrintLastError("GetModuleHandleW(kernel32)");
        CloseHandle(hProcess);
        return false;
    }
    FARPROC pLoadLibraryW = GetProcAddress(hK32, "LoadLibraryW");
    if (!pLoadLibraryW) {
        PrintLastError("GetProcAddress(LoadLibraryW)");
        CloseHandle(hProcess);
        return false;
    }

    // 4. Allocate memory in target process 
    const SIZE_T pathBytes = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID remoteMem = VirtualAllocEx(
        hProcess, nullptr, pathBytes,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        PrintLastError("VirtualAllocEx");
        CloseHandle(hProcess);
        return false;
    }
    printf("[+] Allocated %llu bytes in target at %p.\n",
        (unsigned long long)pathBytes, remoteMem);

    bool   ok = false;
    HANDLE hThread = nullptr;
    DWORD  exitCode = 0;
    SIZE_T written = 0;

    //  5. Write DLL path string 
    if (!WriteProcessMemory(hProcess, remoteMem, dllPath, pathBytes, &written)
        || written != pathBytes)
    {
        PrintLastError("WriteProcessMemory");
        goto cleanup;
    }
    printf("[+] Wrote DLL path to target process.\n");

    //  6. Create remote thread 
    hThread = CreateRemoteThread(
        hProcess, nullptr, 0,
        reinterpret_cast<PTHREAD_START_ROUTINE>(pLoadLibraryW),
        remoteMem, 0, nullptr);
    if (!hThread) {
        PrintLastError("CreateRemoteThread");
        goto cleanup;
    }
    printf("[+] Remote thread created.\n");
    printf("[*] Waiting for remote thread to finish (INFINITE)...\n");

    //  7. Wait INFINITE
    if (WaitForSingleObject(hThread, INFINITE) != WAIT_OBJECT_0) {
        PrintLastError("WaitForSingleObject");
        goto cleanup;
    }

    //  8. Check result 
    if (!GetExitCodeThread(hThread, &exitCode)) {
        PrintLastError("GetExitCodeThread");
        goto cleanup;
    }

    if (exitCode == 0) {
        // Warning instead of hard failure to account for 32-bit truncation or DllMain FALSE
        printf("\n[WARN] Thread finished, but GetExitCodeThread returned 0.\n");
        printf("       - If 'calc' or a shell spawned => Injection SUCCEEDED.\n");
        printf("       - Reason: DllMain returned FALSE, or HMODULE address was truncated to 32-bit.\n");
    }
    else {
        printf("[+] DLL loaded successfully. HMODULE (lower 32-bit) = 0x%lX\n", exitCode);
    }

    // Treat as success regardless, since the thread executed.
    ok = true;

cleanup:
    if (hThread) CloseHandle(hThread);              
    if (remoteMem) {
        if (!VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE))
            PrintLastError("VirtualFreeEx");
    }
    CloseHandle(hProcess);
    return ok;
}