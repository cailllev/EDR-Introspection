// EPIC (Extensible Position Independent Code)
//
// Source: github.com/Print3M/epic
// Author: Print3M
//
#pragma once
#include "wintypes.h"

#define CONTAINING_RECORD(address, type, field) \
    ((type*)((char*)(address) - (ULONG_PTR)(&((type*)0)->field)))

// https://www.vergiliusproject.com/kernels/x64/windows-11/25h2/_LIST_ENTRY
typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY* Flink;  // 0x0
    struct _LIST_ENTRY* Blink;  // 0x8
} LIST_ENTRY, *PLIST_ENTRY;

// https://www.vergiliusproject.com/kernels/x64/windows-11/25h2/_PEB_LDR_DATA
typedef struct _PEB_LDR_DATA {
    ULONG              Length;                           // 0x0
    UCHAR              Initialized;                      // 0x4
    VOID*              SsHandle;                         // 0x8
    struct _LIST_ENTRY InLoadOrderModuleList;            // 0x10
    struct _LIST_ENTRY InMemoryOrderModuleList;          // 0x20
    struct _LIST_ENTRY InInitializationOrderModuleList;  // 0x30
    VOID*              EntryInProgress;                  // 0x40
    UCHAR              ShutdownInProgress;               // 0x48
    VOID*              ShutdownThreadId;                 // 0x50
} PEB_LDR_DATA, *PPEB_LDR_DATA;

// https://www.vergiliusproject.com/kernels/x64/windows-11/25h2/_LDR_DATA_TABLE_ENTRY
typedef struct _LDR_DATA_TABLE_ENTRY {
    struct _LIST_ENTRY     InLoadOrderLinks;            // 0x0
    struct _LIST_ENTRY     InMemoryOrderLinks;          // 0x10
    struct _LIST_ENTRY     InInitializationOrderLinks;  // 0x20
    VOID*                  DllBase;                     // 0x30
    VOID*                  EntryPoint;                  // 0x38
    ULONG                  SizeOfImage;                 // 0x40
    struct _UNICODE_STRING FullDllName;                 // 0x48
    struct _UNICODE_STRING BaseDllName;                 // 0x58
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// https://www.vergiliusproject.com/kernels/x64/windows-11/25h2/_PEB
typedef struct _PEB {
    UCHAR                                InheritedAddressSpace;     // 0x0
    UCHAR                                ReadImageFileExecOptions;  // 0x1
    UCHAR                                BeingDebugged;             // 0x2
    UCHAR                                BitField;                  // 0x3
    UCHAR                                Padding0[4];               // 0x4
    VOID*                                Mutant;                    // 0x8
    VOID*                                ImageBaseAddress;          // 0x10
    struct _PEB_LDR_DATA*                Ldr;                       // 0x18
    struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;         // 0x20
    VOID*                                SubSystemData;             // 0x28
    VOID*                                ProcessHeap;               // 0x30

    // ...
} PEB, *PPEB;

// https://www.vergiliusproject.com/kernels/x64/windows-11/25h2/_IMAGE_DOS_HEADER
typedef struct _IMAGE_DOS_HEADER {
    USHORT e_magic;     // 0x0
    USHORT e_cblp;      // 0x2
    USHORT e_cp;        // 0x4
    USHORT e_crlc;      // 0x6
    USHORT e_cparhdr;   // 0x8
    USHORT e_minalloc;  // 0xa
    USHORT e_maxalloc;  // 0xc
    USHORT e_ss;        // 0xe
    USHORT e_sp;        // 0x10
    USHORT e_csum;      // 0x12
    USHORT e_ip;        // 0x14
    USHORT e_cs;        // 0x16
    USHORT e_lfarlc;    // 0x18
    USHORT e_ovno;      // 0x1a
    USHORT e_res[4];    // 0x1c
    USHORT e_oemid;     // 0x24
    USHORT e_oeminfo;   // 0x26
    USHORT e_res2[10];  // 0x28
    LONG   e_lfanew;    // 0x3c
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

// https://pinvoke.net/default.aspx/Structures.IMAGE_EXPORT_DIRECTORY
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;     // RVA from base of image
    DWORD AddressOfNames;         // RVA from base of image
    DWORD AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

// ---------------- my extensions ----------------- //
#define _WIN64 1
#define WINAPI      __stdcall

#define TRUE  (1==1)
#define FALSE (!TRUE)

// open process
#define PROCESS_ALL_ACCESS ((ULONG)0x001FFFFFL)

typedef LONG NTSTATUS;
#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

#define PAGE_READWRITE 0x04
#define MEM_COMMIT     0x00001000
#define MEM_RESERVE    0x00002000

// NtQueryInformationProcess
typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29
} PROCESSINFOCLASS;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
typedef PROCESS_BASIC_INFORMATION* PPROCESS_BASIC_INFORMATION;

// NtQuerySystemInformation
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45,
    SystemCodeIntegrityInformation = 103,
    SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;

typedef LONG KPRIORITY;

typedef union _LARGE_INTEGER {
    struct {
        DWORD LowPart;
        LONG HighPart;
    } DUMMYSTRUCTNAME;
    struct {
        DWORD LowPart;
        LONG HighPart;
    } u;
    LONGLONG QuadPart;
} LARGE_INTEGER;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

// CreateFileA
#define GENERIC_WRITE                  (0x40000000L)
#define FILE_SHARE_READ                 0x00000001  
#define FILE_SHARE_WRITE                0x00000002  
#define FILE_SHARE_DELETE               0x00000004 

#define CREATE_ALWAYS       2

#define FILE_ATTRIBUTE_NORMAL           0x00000080

#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)

typedef struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
} SECURITY_ATTRIBUTES, * PSECURITY_ATTRIBUTES, * LPSECURITY_ATTRIBUTES;

// minidump
typedef enum _MINIDUMP_TYPE {
    MiniDumpNormal = 0x00000000,
    MiniDumpWithDataSegs = 0x00000001,
    MiniDumpWithFullMemory = 0x00000002,
    MiniDumpWithHandleData = 0x00000004,
    MiniDumpFilterMemory = 0x00000008,
    MiniDumpScanMemory = 0x00000010,
    MiniDumpWithUnloadedModules = 0x00000020,
    MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
    MiniDumpFilterModulePaths = 0x00000080,
    MiniDumpWithProcessThreadData = 0x00000100,
    MiniDumpWithPrivateReadWriteMemory = 0x00000200,
    MiniDumpWithoutOptionalData = 0x00000400,
    MiniDumpWithFullMemoryInfo = 0x00000800,
    MiniDumpWithThreadInfo = 0x00001000,
    MiniDumpWithCodeSegs = 0x00002000,
    MiniDumpWithoutAuxiliaryState = 0x00004000,
    MiniDumpWithFullAuxiliaryState = 0x00008000,
    MiniDumpWithPrivateWriteCopyMemory = 0x00010000,
    MiniDumpIgnoreInaccessibleMemory = 0x00020000,
    MiniDumpWithTokenInformation = 0x00040000,
    MiniDumpWithModuleHeaders = 0x00080000,
    MiniDumpFilterTriage = 0x00100000,
    MiniDumpWithAvxXStateContext = 0x00200000,
    MiniDumpWithIptTrace = 0x00400000,
    MiniDumpScanInaccessiblePartialPages = 0x00800000,
    MiniDumpFilterWriteCombinedMemory = 0x01000000,
    MiniDumpValidTypeFlags = 0x01ffffff,
    MiniDumpNoIgnoreInaccessibleMemory = 0x02000000,
    MiniDumpValidTypeFlagsEx = 0x03ffffff,
} MINIDUMP_TYPE;

/*
typedef struct _MINIDUMP_EXCEPTION_INFORMATION* PMINIDUMP_EXCEPTION_INFORMATION;
typedef struct _MINIDUMP_USER_STREAM_INFORMATION* PMINIDUMP_USER_STREAM_INFORMATION;
typedef struct _MINIDUMP_CALLBACK_INFORMATION* PMINIDUMP_CALLBACK_INFORMATION;
*/

/*
#define EXCEPTION_MAXIMUM_PARAMETERS 15 // maximum number of exception parameters

typedef struct _EXCEPTION_RECORD {
    DWORD    ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD* ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD;

typedef EXCEPTION_RECORD* PEXCEPTION_RECORD;

#if defined(_MSC_VER)
#define DECLSPEC_ALIGN(x) __declspec(align(x))
#else
#define DECLSPEC_ALIGN(x) __attribute__((aligned(x)))
#endif

typedef struct DECLSPEC_ALIGN(16) _M128A {
    ULONGLONG Low;
    LONGLONG High;
} M128A, * PM128A;

typedef struct DECLSPEC_ALIGN(16) _XSAVE_FORMAT {
    WORD   ControlWord;
    WORD   StatusWord;
    BYTE  TagWord;
    BYTE  Reserved1;
    WORD   ErrorOpcode;
    DWORD ErrorOffset;
    WORD   ErrorSelector;
    WORD   Reserved2;
    DWORD DataOffset;
    WORD   DataSelector;
    WORD   Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    M128A FloatRegisters[8];

#if defined(_WIN64)

    M128A XmmRegisters[16];
    BYTE  Reserved4[96];

#else

    M128A XmmRegisters[8];
    BYTE  Reserved4[224];

#endif

} XSAVE_FORMAT, * PXSAVE_FORMAT;

typedef XSAVE_FORMAT XMM_SAVE_AREA32, * PXMM_SAVE_AREA32;

typedef struct DECLSPEC_ALIGN(16) _CONTEXT {

    //
    // Register parameter home addresses.
    //
    // N.B. These fields are for convience - they could be used to extend the
    //      context record in the future.
    //

    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;

    //
    // Control flags.
    //

    DWORD ContextFlags;
    DWORD MxCsr;

    //
    // Segment Registers and processor flags.
    //

    WORD   SegCs;
    WORD   SegDs;
    WORD   SegEs;
    WORD   SegFs;
    WORD   SegGs;
    WORD   SegSs;
    DWORD EFlags;

    //
    // Debug registers
    //

    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;

    //
    // Integer registers.
    //

    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;

    //
    // Program counter.
    //

    DWORD64 Rip;

    //
    // Floating point state.
    //

    union {
        XMM_SAVE_AREA32 FltSave;
        struct {
            M128A Header[2];
            M128A Legacy[8];
            M128A Xmm0;
            M128A Xmm1;
            M128A Xmm2;
            M128A Xmm3;
            M128A Xmm4;
            M128A Xmm5;
            M128A Xmm6;
            M128A Xmm7;
            M128A Xmm8;
            M128A Xmm9;
            M128A Xmm10;
            M128A Xmm11;
            M128A Xmm12;
            M128A Xmm13;
            M128A Xmm14;
            M128A Xmm15;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

    //
    // Vector registers.
    //

    M128A VectorRegister[26];
    DWORD64 VectorControl;

    //
    // Special debug control registers.
    //

    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
} CONTEXT, *PCONTEXT;

typedef struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
} EXCEPTION_POINTERS, * PEXCEPTION_POINTERS;

typedef struct _MINIDUMP_EXCEPTION_INFORMATION {
    DWORD ThreadId;
    PEXCEPTION_POINTERS ExceptionPointers;
    BOOL ClientPointers;
} MINIDUMP_EXCEPTION_INFORMATION, * PMINIDUMP_EXCEPTION_INFORMATION;

typedef struct _MINIDUMP_USER_STREAM {
    ULONG32 Type;
    ULONG BufferSize;
    PVOID Buffer;
} MINIDUMP_USER_STREAM, * PMINIDUMP_USER_STREAM;

typedef struct _MINIDUMP_USER_STREAM_INFORMATION {
    ULONG UserStreamCount;
    PMINIDUMP_USER_STREAM UserStreamArray;
} MINIDUMP_USER_STREAM_INFORMATION, * PMINIDUMP_USER_STREAM_INFORMATION;

typedef struct _MINIDUMP_THREAD_CALLBACK {
    ULONG ThreadId;
    HANDLE ThreadHandle;
#if defined(_ARM64_)
    ULONG Pad;
#endif
    CONTEXT Context;
    ULONG SizeOfContext;
    ULONG64 StackBase;
    ULONG64 StackEnd;
} MINIDUMP_THREAD_CALLBACK, * PMINIDUMP_THREAD_CALLBACK;

typedef struct _MINIDUMP_THREAD_EX_CALLBACK {
    ULONG ThreadId;
    HANDLE ThreadHandle;
#if defined(_ARM64_)
    ULONG Pad;
#endif
    CONTEXT Context;
    ULONG SizeOfContext;
    ULONG64 StackBase;
    ULONG64 StackEnd;
    ULONG64 BackingStoreBase;
    ULONG64 BackingStoreEnd;
} MINIDUMP_THREAD_EX_CALLBACK, * PMINIDUMP_THREAD_EX_CALLBACK;

typedef struct tagVS_FIXEDFILEINFO {
    DWORD   dwSignature;
    DWORD   dwStrucVersion;
    DWORD   dwFileVersionMS;
    DWORD   dwFileVersionLS;
    DWORD   dwProductVersionMS;
    DWORD   dwProductVersionLS;
    DWORD   dwFileFlagsMask;
    DWORD   dwFileFlags;
    DWORD   dwFileOS;
    DWORD   dwFileType;
    DWORD   dwFileSubtype;
    DWORD   dwFileDateMS;
    DWORD   dwFileDateLS;
} VS_FIXEDFILEINFO;

typedef struct _MINIDUMP_MODULE_CALLBACK {
    PWCHAR FullPath;
    ULONG64 BaseOfImage;
    ULONG SizeOfImage;
    ULONG CheckSum;
    ULONG TimeDateStamp;
    VS_FIXEDFILEINFO VersionInfo;
    PVOID CvRecord;
    ULONG SizeOfCvRecord;
    PVOID MiscRecord;
    ULONG SizeOfMiscRecord;
} MINIDUMP_MODULE_CALLBACK, * PMINIDUMP_MODULE_CALLBACK;

typedef struct _MINIDUMP_INCLUDE_THREAD_CALLBACK {
    ULONG ThreadId;
} MINIDUMP_INCLUDE_THREAD_CALLBACK, * PMINIDUMP_INCLUDE_THREAD_CALLBACK;

typedef struct _MINIDUMP_INCLUDE_MODULE_CALLBACK {
    ULONG64 BaseOfImage;
} MINIDUMP_INCLUDE_MODULE_CALLBACK, * PMINIDUMP_INCLUDE_MODULE_CALLBACK;

typedef struct _MINIDUMP_IO_CALLBACK {
    HANDLE Handle;
    ULONG64 Offset;
    PVOID Buffer;
    ULONG BufferBytes;
} MINIDUMP_IO_CALLBACK, * PMINIDUMP_IO_CALLBACK;

typedef struct _MINIDUMP_READ_MEMORY_FAILURE_CALLBACK {
    ULONG64 Offset;
    ULONG Bytes;
    HRESULT FailureStatus;
} MINIDUMP_READ_MEMORY_FAILURE_CALLBACK,
* PMINIDUMP_READ_MEMORY_FAILURE_CALLBACK;

typedef struct _MINIDUMP_VM_QUERY_CALLBACK {
    ULONG64 Offset;
} MINIDUMP_VM_QUERY_CALLBACK, * PMINIDUMP_VM_QUERY_CALLBACK;

typedef struct _MINIDUMP_VM_PRE_READ_CALLBACK {
    ULONG64 Offset;
    PVOID Buffer;
    ULONG Size;
} MINIDUMP_VM_PRE_READ_CALLBACK, * PMINIDUMP_VM_PRE_READ_CALLBACK;

typedef struct _MINIDUMP_VM_POST_READ_CALLBACK {
    ULONG64 Offset;
    PVOID Buffer;
    ULONG Size;
    ULONG Completed;
    HRESULT Status;
} MINIDUMP_VM_POST_READ_CALLBACK, * PMINIDUMP_VM_POST_READ_CALLBACK;

typedef struct _MINIDUMP_CALLBACK_INPUT {
    ULONG ProcessId;
    HANDLE ProcessHandle;
    ULONG CallbackType;
    union {
        HRESULT Status;
        MINIDUMP_THREAD_CALLBACK Thread;
        MINIDUMP_THREAD_EX_CALLBACK ThreadEx;
        MINIDUMP_MODULE_CALLBACK Module;
        MINIDUMP_INCLUDE_THREAD_CALLBACK IncludeThread;
        MINIDUMP_INCLUDE_MODULE_CALLBACK IncludeModule;
        MINIDUMP_IO_CALLBACK Io;
        MINIDUMP_READ_MEMORY_FAILURE_CALLBACK ReadMemoryFailure;
        ULONG SecondaryFlags;
        MINIDUMP_VM_QUERY_CALLBACK VmQuery;
        MINIDUMP_VM_PRE_READ_CALLBACK VmPreRead;
        MINIDUMP_VM_POST_READ_CALLBACK VmPostRead;
    };
} MINIDUMP_CALLBACK_INPUT, * PMINIDUMP_CALLBACK_INPUT;

typedef struct _MINIDUMP_MEMORY_INFO {
    ULONG64 BaseAddress;
    ULONG64 AllocationBase;
    ULONG32 AllocationProtect;
    ULONG32 __alignment1;
    ULONG64 RegionSize;
    ULONG32 State;
    ULONG32 Protect;
    ULONG32 Type;
    ULONG32 __alignment2;
} MINIDUMP_MEMORY_INFO, * PMINIDUMP_MEMORY_INFO;

typedef struct _MINIDUMP_CALLBACK_OUTPUT {
    union {
        ULONG ModuleWriteFlags;
        ULONG ThreadWriteFlags;
        ULONG SecondaryFlags;
        struct {
            ULONG64 MemoryBase;
            ULONG MemorySize;
        };
        struct {
            BOOL CheckCancel;
            BOOL Cancel;
        };
        HANDLE Handle;
        struct {
            MINIDUMP_MEMORY_INFO VmRegion;
            BOOL Continue;
        };
        struct {
            HRESULT VmQueryStatus;
            MINIDUMP_MEMORY_INFO VmQueryResult;
        };
        struct {
            HRESULT VmReadStatus;
            ULONG VmReadBytesCompleted;
        };
        HRESULT Status;
    };
} MINIDUMP_CALLBACK_OUTPUT, * PMINIDUMP_CALLBACK_OUTPUT;

typedef BOOL(WINAPI* MINIDUMP_CALLBACK_ROUTINE) (
    PVOID CallbackParam,
    PMINIDUMP_CALLBACK_INPUT CallbackInput,
    PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
    );

typedef struct _MINIDUMP_CALLBACK_INFORMATION {
    MINIDUMP_CALLBACK_ROUTINE CallbackRoutine;
    PVOID CallbackParam;
} MINIDUMP_CALLBACK_INFORMATION, * PMINIDUMP_CALLBACK_INFORMATION;
*/