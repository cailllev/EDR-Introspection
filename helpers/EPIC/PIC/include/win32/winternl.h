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

// resolve delayload DLLs
typedef void* FARPROC;

#define IMAGE_DOS_SIGNATURE 0x5A4D     // "MZ"
#define IMAGE_NT_SIGNATURE  0x00004550 // "PE\0\0"

typedef struct _IMAGE_FILE_HEADER {
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

#ifndef IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13
#endif

typedef struct _MY_IMAGE_DELAYLOAD_DESCRIPTOR {
    union {
        DWORD AllAttributes;
        struct {
            DWORD RvaAttributes;
        };
    } Attributes;
    DWORD DllNameRVA;
    DWORD ModuleHandleRVA;
    DWORD ImportAddressTableRVA;    // RVA to IAT (where function pointers go)
    DWORD ImportNameTableRVA;       // RVA to names (IMAGE_IMPORT_BY_NAME or ordinals)
    DWORD BoundIATRVA;
    DWORD UnloadIATRVA;
    DWORD TimeStamp;
} MY_IMAGE_DELAYLOAD_DESCRIPTOR, * PMY_IMAGE_DELAYLOAD_DESCRIPTOR;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD  Magic;
    BYTE  MajorLinkerVersion;
    BYTE  MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    ULONGLONG ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;                // IMAGE_NT_SIGNATURE
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD Hint;
    BYTE Name[1];
} IMAGE_IMPORT_BY_NAME, * PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_THUNK_DATA64 {
    union {
        ULONGLONG ForwarderString;  // PBYTE 
        ULONGLONG Function;         // PDWORD
        ULONGLONG Ordinal;
        ULONGLONG AddressOfData;    // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA64;
typedef IMAGE_THUNK_DATA64* PIMAGE_THUNK_DATA64;

#define IMAGE_ORDINAL_FLAG64 0x8000000000000000ULL

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    DWORD   OriginalFirstThunk;
    DWORD   TimeDateStamp;
    DWORD   ForwarderChain;
    DWORD   Name;
    DWORD   FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR, * PIMAGE_IMPORT_DESCRIPTOR;


typedef struct _IMAGE_DELAYLOAD_DESCRIPTOR {
    DWORD Attributes;
    DWORD DllNameRVA;
    DWORD ModuleHandleRVA;
    DWORD ImportAddressTableRVA;
    DWORD ImportNameTableRVA;
    DWORD BoundImportAddressTableRVA;
    DWORD UnloadInformationTableRVA;
    DWORD TimeStamp;
} IMAGE_DELAYLOAD_DESCRIPTOR, * PIMAGE_DELAYLOAD_DESCRIPTOR;

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
