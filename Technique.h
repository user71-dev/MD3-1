#pragma once
#include <Windows.h>
//#include <winternl.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <threadpoolapiset.h>

typedef struct _LSA_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

using myNtCreateSection = NTSTATUS(NTAPI*)(
    OUT PHANDLE SectionHandle,
    IN ULONG DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG PageAttributess,
    IN ULONG SectionAttributes,
    IN HANDLE FileHandle OPTIONAL
    );

using myNtMapViewOfSection = NTSTATUS(NTAPI*)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
    );

using myRtlCreateUserThread = NTSTATUS(NTAPI*)(
    IN HANDLE ProcessHandle,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    IN BOOLEAN CreateSuspended,
    IN ULONG StackZeroBits,
    IN OUT PULONG StackReserved,
    IN OUT PULONG StackCommit,
    IN PVOID StartAddress,
    IN PVOID StartParameter OPTIONAL,
    OUT PHANDLE ThreadHandle,
    OUT PCLIENT_ID ClientID
    );

using myNtQueryInformationWorkerFactory = NTSTATUS(NTAPI*)(
    HANDLE WorkerFactoryHandle,
    ULONG WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,
    ULONG WorkerFactoryInformationLength,
    PULONG ReturnLength
    );

using myNtSetInformationWorkerFactory = NTSTATUS(NTAPI*)(
    HANDLE WorkerFactoryHandle,
    ULONG WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,
    ULONG WorkerFactoryInformationLength
    );

using myNtQuerySystemInformation = NTSTATUS(NTAPI*)(
    IN ULONG SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );

// ============================================================
// Thêm cho Variant 1 - dùng NtQueryInformationProcess
// ============================================================
using myNtQueryInformationProcess = NTSTATUS(NTAPI*)(
    IN HANDLE ProcessHandle,
    IN ULONG ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );

typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO {
    HANDLE      HandleValue;
    ULONG_PTR   HandleCount;
    ULONG_PTR   PointerCount;
    ACCESS_MASK GrantedAccess;
    ULONG       ObjectTypeIndex;
    ULONG       HandleAttributes;
    ULONG       Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

#define PROCESS_HANDLE_INFORMATION_CLASS 51
#define WORKER_FACTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectAllInformation,
    ObjectDataInformation
} OBJECT_INFORMATION_CLASS, * POBJECT_INFORMATION_CLASS;

using myNtQueryObject = NTSTATUS(NTAPI*)(
    IN HANDLE ObjectHandle,
    IN ULONG ObjectInformationClass,
    OUT PVOID ObjectInformation,
    IN ULONG Length,
    OUT PULONG ReturnLength
    );

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

#define WORKER_FACTORY_BASIC_INFORMATION_CLASS 7
#define WORKER_FACTORY_THREAD_MINIMUM_CLASS 4

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    UCHAR TypeIndex;
    CHAR ReservedByte;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _WORKER_FACTORY_BASIC_INFORMATION {
    LARGE_INTEGER Timeout;
    LARGE_INTEGER RetryTimeout;
    LARGE_INTEGER IdleTimeout;
    BOOLEAN       Paused;
    BOOLEAN       TimerSet;
    BOOLEAN       QueuedToExWorker;
    BOOLEAN       MayCreate;
    BOOLEAN       CreateInProgress;
    BOOLEAN       InsertedIntoQueue;
    BOOLEAN       Shutdown;
    ULONG         BindingCount;
    ULONG         ThreadMinimum;
    ULONG         ThreadMaximum;
    ULONG         PendingWorkerCount;
    ULONG         WaitingWorkerCount;
    ULONG         TotalWorkerCount;
    ULONG         ReleaseCount;
    LONGLONG      InfiniteWaitGoal;
    PVOID         StartRoutine;          // offset 0x48 trên x64
    PVOID         StartParameter;
    HANDLE        ProcessId;
    SIZE_T        StackReserve;
    SIZE_T        StackCommit;
    NTSTATUS      LastThreadCreationStatus;
} WORKER_FACTORY_BASIC_INFORMATION, * PWORKER_FACTORY_BASIC_INFORMATION;

static_assert(sizeof(WORKER_FACTORY_BASIC_INFORMATION) == 120,
    "WORKER_FACTORY_BASIC_INFORMATION must be exactly 120 bytes on x64");

BOOL InjectThreadpool(const std::vector<unsigned char>& shellcode, DWORD targetPid);

BOOL InjectSectionMapping(const std::vector<unsigned char>& shellcode, DWORD targetPid);