#include <windows.h>
#include <intrin.h>
#include <psapi.h>
#include <tchar.h>
#include <iostream>
#include <map>
#include <stdio.h>
#include <stdint.h>
#include <string>
#include <chrono>

#include <MinHook.h>
#include <TraceLoggingProvider.h>

#pragma intrinsic(_ReturnAddress)

// ------------------ REFL INJ ------------------ //
// from https://github.com/Reijaff/offensive_c/blob/main/dll_reflective_loader_64.c
typedef struct _LSA_UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _LDR_MODULE
{
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID BaseAddress;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    ULONG Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    PVOID Handle;
} CURDIR, * PCURDIR;

typedef struct _STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} ANSI_STRING, * PANSI_STRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    WORD Flags;
    WORD Length;
    ULONG TimeStamp;
    ANSI_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    PVOID ConsoleHandle;
    ULONG ConsoleFlags;
    PVOID StandardInput;
    PVOID StandardOutput;
    PVOID StandardError;
    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
    ULONG EnvironmentSize;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN Spare;
    HANDLE Mutant;
    PVOID ImageBase;
    PPEB_LDR_DATA LoaderData;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID FastPebLockRoutine;
    PVOID FastPebUnlockRoutine;
    ULONG EnvironmentUpdateCount;
    PVOID* KernelCallbackTable;
    PVOID EventLogSection;
    PVOID EventLog;
    PVOID FreeList;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[0x2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID ReadOnlySharedMemoryHeap;
    PVOID* ReadOnlyServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    BYTE Spare2[0x4];
    LARGE_INTEGER CriticalSectionTimeout;
    ULONG HeapSegmentReserve;
    ULONG HeapSegmentCommit;
    ULONG HeapDeCommitTotalFreeThreshold;
    ULONG HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID** ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    PVOID GdiDCAttributeList;
    PVOID LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    ULONG OSBuildNumber;
    ULONG OSPlatformId;
    ULONG ImageSubSystem;
    ULONG ImageSubSystemMajorVersion;
    ULONG ImageSubSystemMinorVersion;
    ULONG GdiHandleBuffer[0x22];
    ULONG PostProcessInitRoutine;
    ULONG TlsExpansionBitmap;
    BYTE TlsExpansionBitmapBits[0x80];
    ULONG SessionId;
} PEB, * PPEB;

typedef struct BASE_RELOCATION_BLOCK
{
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY
{
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

///
__declspec(noinline) static DWORD64 get_current_address()
{
    return (DWORD64)_ReturnAddress();
}

inline void zero_memory(DWORD64 Destination, SIZE_T Size)
{
    PULONG Dest = (PULONG)Destination;
    SIZE_T Count = Size / sizeof(ULONG);

    while (Count > 0)
    {
        *Dest = 0;
        Dest++;
        Count--;
    }
}

inline SIZE_T wchar_to_char(PCHAR Destination, PWCHAR Source, SIZE_T MaximumAllowed)
{
    INT Length = (INT)MaximumAllowed;

    while (--Length >= 0)
    {
        if (!(*Destination++ = *Source++))
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}

inline INT string_compare_a(LPCSTR String1, LPCSTR String2)
{
    for (; *String1 == *String2; String1++, String2++)
    {
        if (*String1 == '\0')
            return 0;
    }

    return ((*(LPCSTR)String1 < *(LPCSTR)String2) ? -1 : +1);
}

inline DWORD64 get_module_handle_a(char* lpModuleName)
{
    PPEB Peb = (PPEB)__readgsqword(0x60);
    PLDR_MODULE Module = NULL;
    CHAR wDllName[64] = { 0 };
    PLIST_ENTRY Head = &Peb->LoaderData->InMemoryOrderModuleList;
    PLIST_ENTRY Next = Head->Flink;
    Module = (PLDR_MODULE)((PBYTE)Next - 16);

    while (Next != Head)
    {
        Module = (PLDR_MODULE)((PBYTE)Next - 16);
        if (Module->BaseDllName.Buffer != NULL)
        {
            zero_memory((DWORD64)wDllName, sizeof(wDllName));
            wchar_to_char(wDllName, Module->BaseDllName.Buffer, 64);
            if (string_compare_a(lpModuleName, wDllName) == 0)
                return (DWORD64)Module->BaseAddress;
        }
        Next = Next->Flink;
    }

    return 0;
}

inline BOOL rtl_load_pe_headers(PIMAGE_DOS_HEADER* Dos, PIMAGE_NT_HEADERS* Nt, PIMAGE_FILE_HEADER* File, PIMAGE_OPTIONAL_HEADER* Optional, PBYTE* ImageBase)
{
    *Dos = (PIMAGE_DOS_HEADER)*ImageBase;
    if ((*Dos)->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    *Nt = (PIMAGE_NT_HEADERS)((PBYTE)*Dos + (*Dos)->e_lfanew);
    if ((*Nt)->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    *File = (PIMAGE_FILE_HEADER)(*ImageBase + (*Dos)->e_lfanew + sizeof(DWORD));
    *Optional = (PIMAGE_OPTIONAL_HEADER)((PBYTE)*File + sizeof(IMAGE_FILE_HEADER));

    return TRUE;
}

inline DWORD64 get_proc_address_a(DWORD64 ModuleBase, LPCSTR lpProcName)
{
    PBYTE pFunctionName = NULL;
    PIMAGE_DOS_HEADER Dos = NULL;
    PIMAGE_NT_HEADERS Nt = NULL;
    PIMAGE_FILE_HEADER File = NULL;
    PIMAGE_OPTIONAL_HEADER Optional = NULL;

    rtl_load_pe_headers(&Dos, &Nt, &File, &Optional, (PBYTE*)&ModuleBase);

    IMAGE_EXPORT_DIRECTORY* ExportTable = (PIMAGE_EXPORT_DIRECTORY)(ModuleBase + Optional->DataDirectory[0].VirtualAddress);
    PDWORD FunctionNameAddressArray = (PDWORD)((LPBYTE)ModuleBase + ExportTable->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)((LPBYTE)ModuleBase + ExportTable->AddressOfFunctions);
    PWORD FunctionOrdinalAddressArray = (PWORD)((LPBYTE)ModuleBase + ExportTable->AddressOfNameOrdinals);

    for (DWORD dwX = 0; dwX < ExportTable->NumberOfNames; dwX++)
    {
        pFunctionName = FunctionNameAddressArray[dwX] + (PBYTE)ModuleBase;
        if (string_compare_a((PCHAR)pFunctionName, lpProcName) == 0)
            return ((DWORD64)ModuleBase + FunctionAddressArray[FunctionOrdinalAddressArray[dwX]]);
    }

    return 0;
}

inline DWORD64 copy_memory(DWORD64 Destination, DWORD64 Source, SIZE_T Length)
{
    PBYTE D = (PBYTE)Destination;
    PBYTE S = (PBYTE)Source;

    while (Length--)
        *D++ = *S++;

    return Destination;
}

typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef FARPROC(WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI* VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* entry_DLLMAIN)(HINSTANCE, DWORD, LPVOID);

extern "C" __declspec(dllexport)
void ReflectiveLoader()
{
    // 0. calculate image address

    DWORD64 dll_image_address;
    PIMAGE_NT_HEADERS nt_headers_address;

    dll_image_address = get_current_address();

    while (TRUE)
    {
        if (((PIMAGE_DOS_HEADER)dll_image_address)->e_magic == IMAGE_DOS_SIGNATURE)
        {
            nt_headers_address = (PIMAGE_NT_HEADERS)(dll_image_address + ((PIMAGE_DOS_HEADER)dll_image_address)->e_lfanew);
            if (nt_headers_address->Signature == IMAGE_NT_SIGNATURE)
                break;
        }
        dll_image_address--;
    }

    // 1. resolve system functions
    char KERNEL32_DLL_string[] = { '\x4b', '\x45', '\x52', '\x4e', '\x45', '\x4c', '\x33', '\x32', '\x2e', '\x44', '\x4c', '\x4c', 0 };                   // KERNEL32.DLL
    char VirtualAlloc_string[] = { '\x56', '\x69', '\x72', '\x74', '\x75', '\x61', '\x6c', '\x41', '\x6c', '\x6c', '\x6f', '\x63', 0 };                   // VirtualAlloc
    char GetProcAddress_string[] = { '\x47', '\x65', '\x74', '\x50', '\x72', '\x6f', '\x63', '\x41', '\x64', '\x64', '\x72', '\x65', '\x73', '\x73', 0 }; // GetProcAddress
    char LoadLibraryA_string[] = { '\x4c', '\x6f', '\x61', '\x64', '\x4c', '\x69', '\x62', '\x72', '\x61', '\x72', '\x79', '\x41', 0 };                   // LoadLibraryA

    DWORD64 kernel32 = get_module_handle_a(KERNEL32_DLL_string);
    LOADLIBRARYA pLoadLibraryA = (LOADLIBRARYA)get_proc_address_a(kernel32, LoadLibraryA_string);
    GETPROCADDRESS pGetProcAddress = (GETPROCADDRESS)get_proc_address_a(kernel32, GetProcAddress_string);
    VIRTUALALLOC pVirtualAlloc = (VIRTUALALLOC)get_proc_address_a(kernel32, VirtualAlloc_string);

    // 2. allocate memory for loading dll
    DWORD64 dll_base = (DWORD64)pVirtualAlloc(NULL, nt_headers_address->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // 3. copy headers
    copy_memory(dll_base, dll_image_address, nt_headers_address->OptionalHeader.SizeOfHeaders);

    // 4. copy sections
    DWORD64 section_virtual_address;
    DWORD64 section_data_address;
    PIMAGE_SECTION_HEADER section_header_address = IMAGE_FIRST_SECTION(nt_headers_address);
    for (; section_header_address->VirtualAddress != (DWORD64)NULL; section_header_address++)
    {
        section_virtual_address = dll_base + section_header_address->VirtualAddress;
        section_data_address = dll_image_address + section_header_address->PointerToRawData;
        copy_memory(section_virtual_address, section_data_address, section_header_address->SizeOfRawData);
    }

    // 5. resolve import address table
    IMAGE_DATA_DIRECTORY imports_data_directory = nt_headers_address->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(dll_base + imports_data_directory.VirtualAddress);
    LPCSTR library_name;
    HMODULE library_address;
    PIMAGE_THUNK_DATA thunk_data_address;
    PIMAGE_IMPORT_BY_NAME import_by_name_address;

    for (; import_descriptor->Name != (DWORD64)NULL; import_descriptor++)
    {
        library_name = (LPCSTR)(dll_base + import_descriptor->Name);
        library_address = pLoadLibraryA(library_name);

        if (library_address)
        {
            thunk_data_address = (PIMAGE_THUNK_DATA)(dll_base + import_descriptor->FirstThunk);

            for (; thunk_data_address->u1.AddressOfData != (DWORD64)NULL; thunk_data_address++)
            {
                import_by_name_address = (PIMAGE_IMPORT_BY_NAME)(dll_base + thunk_data_address->u1.AddressOfData);
                thunk_data_address->u1.Function = (DWORD64)pGetProcAddress(library_address, import_by_name_address->Name);
            }
        }
    }

    // 6. process all relocations

    // dummy_va = dummy_base + rva
    // dummy_va - dummy_base = rva
    // (dummy_va - dummy_base) + true_base = rva + true_base
    // dummy_va + (true_base - dummy_base) = rva + true_base
    DWORD64 base_diff = dll_base - nt_headers_address->OptionalHeader.ImageBase; // true_base - dummy_base

    IMAGE_DATA_DIRECTORY reloc_data_directory = nt_headers_address->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    PIMAGE_BASE_RELOCATION base_reloc_address;
    PBASE_RELOCATION_ENTRY reloc_entry_address;
    DWORD64 reloc_block_address;
    DWORD64 reloc_block_entry_count;

    // check if any relocations present
    if (reloc_data_directory.Size)
    {
        base_reloc_address = (PIMAGE_BASE_RELOCATION)(dll_base + reloc_data_directory.VirtualAddress);

        while (base_reloc_address->SizeOfBlock)
        {
            reloc_block_address = dll_base + base_reloc_address->VirtualAddress;
            reloc_block_entry_count = (base_reloc_address->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);

            reloc_entry_address = (PBASE_RELOCATION_ENTRY)((DWORD64)base_reloc_address + sizeof(IMAGE_BASE_RELOCATION));
            while (reloc_block_entry_count--)
            {
                if (reloc_entry_address->Type == IMAGE_REL_BASED_DIR64)
                    *(DWORD64*)(reloc_block_address + reloc_entry_address->Offset) += base_diff; // reloc_entry = dummy_va + (true_base - dummy_base)

                reloc_entry_address = (PBASE_RELOCATION_ENTRY)((DWORD64)reloc_entry_address + sizeof(BASE_RELOCATION_ENTRY));
            }
            base_reloc_address = (PIMAGE_BASE_RELOCATION)((DWORD64)base_reloc_address + base_reloc_address->SizeOfBlock);
        }
    }

    // 7. call entry point
    DWORD64 entrypoint_address = dll_base + nt_headers_address->OptionalHeader.AddressOfEntryPoint;
    ((entry_DLLMAIN)entrypoint_address)((HINSTANCE)dll_base, DLL_PROCESS_ATTACH, NULL);
}

// ------------------ HOOKS ------------------ //
static UINT64 pid;

TRACELOGGING_DEFINE_PROVIDER(
    g_hProvider,
    "Hook-Provider", // name in the ETW, cannot be a variable
    (0x72248411, 0x7166, 0x4feb, 0xa3, 0x86, 0x34, 0xd8, 0xf3, 0x5b, 0xb6, 0x37)  // this cannot be a variable
);

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    } DUMMYUNIONNAME;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE)(
    PVOID           ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG           Reserved
    );

// hooked function definitions
typedef NTSTATUS(NTAPI* PFN_NtOpenFile)(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    ULONG              ShareAccess,
    ULONG              OpenOptions
    );

typedef NTSTATUS(NTAPI* PFN_NtReadFile)(
    HANDLE           FileHandle,
    HANDLE           Event,
    PIO_APC_ROUTINE  ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            Buffer,
    ULONG            Length,
    PLARGE_INTEGER   ByteOffset,
    PULONG           Key
    );

typedef NTSTATUS(NTAPI* PFN_NtOpenProcess)(
    PHANDLE     ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PVOID       ObjectAttributes,
    PVOID       ClientId
    );

typedef NTSTATUS(NTAPI* PFN_NtReadVirtualMemory)(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
    );

typedef NTSTATUS(NTAPI* PFN_NtWriteVirtualMemory)(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
    );

typedef NTSTATUS(NTAPI* PFN_NtClose)(
    HANDLE Handle
    );

typedef NTSTATUS(NTAPI* PFN_NtTerminateProcess)(
    HANDLE   ProcessHandle,
    NTSTATUS ExitStatus
    );

// trampolines created by MinHook
static PFN_NtOpenFile g_origNtOpenFile = nullptr;
static PFN_NtReadFile g_origNtReadFile = nullptr;
static PFN_NtOpenProcess g_origNtOpenProcess = nullptr;
static PFN_NtReadVirtualMemory g_origNtReadVirtualMemory = nullptr;
static PFN_NtWriteVirtualMemory g_origNtWriteVirtualMemory = nullptr;
static PFN_NtClose g_origNtClose = nullptr;
static PFN_NtTerminateProcess g_origNtTerminateProcess = nullptr;

UINT64 get_ns_time() {
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
}

void emit_etw_ok(std::string msg) {
    UINT64 ns = get_ns_time();
    TraceLoggingWrite(
        g_hProvider,
        "EDRHookTask", // the first event name is used for all events, unless using a manifest file
        TraceLoggingString(msg.c_str(), "message"),
        TraceLoggingUInt64(ns, "ns_since_epoch"),
        TraceLoggingUInt64(pid, "targetpid")
    );
    std::cout << "[+] Hook-DLL: " << msg << "\n";
};

void emit_etw_error(std::string error) {
    UINT64 ns = get_ns_time();
    TraceLoggingWrite(
        g_hProvider,
        "EDRHookError",
        TraceLoggingString(error.c_str(), "message"),
        TraceLoggingUInt64(ns, "ns_since_epoch"),
        TraceLoggingUInt64(pid, "targetpid")
    );
    std::cerr << "[!] Hook-DLL: " << error << "\n";
};

void emit_etw_msg(const char msg[], UINT64 tpid) {
    UINT64 ns = get_ns_time();
    TraceLoggingWrite(
        g_hProvider,
        "EDRHookTask", 
        TraceLoggingString(msg, "message"),
        TraceLoggingUInt64(ns, "ns_since_epoch"),
        TraceLoggingUInt64(tpid, "targetpid")
    );
};

NTSTATUS NTAPI Hook_NtOpenFile(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    ULONG              ShareAccess,
    ULONG              OpenOptions
) {
    char msg[128];
    wchar_t filename[512] = L"(unknown)";

    if (FileHandle && *FileHandle) {
        HANDLE h = *FileHandle;
        // Try to resolve full path
        if (GetFinalPathNameByHandleW(h, filename, _countof(filename), FILE_NAME_NORMALIZED) == 0) {
            wcsncpy_s(filename, L"(unknown)", _TRUNCATE);
        }
    }
    else if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer) {
        // fallback to ObjectAttributes name if handle resolution fails
        wcsncpy_s(filename, ObjectAttributes->ObjectName->Buffer, _TRUNCATE);
    }

    _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtOpenFile (%ls) with 0x%X", filename, static_cast<unsigned int>(DesiredAccess));
    emit_etw_msg(msg, pid);

	// TODO strip access when MsMpEng tries to open itself? Maybe tries to reload ntdll?

    return g_origNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}

NTSTATUS NTAPI Hook_NtReadFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
) {

    char msg[128];
    wchar_t filename[512] = L"(unknown)";

    if (FileHandle) {
        if (GetFinalPathNameByHandleW(FileHandle, filename, _countof(filename), FILE_NAME_NORMALIZED) == 0) {
            wcsncpy_s(filename, L"(unknown)", _TRUNCATE);
        }
    }

    unsigned long long offsetVal = ByteOffset ? (unsigned long long)ByteOffset->QuadPart : 0;
    _snprintf_s(msg, sizeof(msg), _TRUNCATE,
        ByteOffset ? "NtReadFile (%ls) at 0x%llx" : "NtReadFile (%ls) at NULL",
        filename, offsetVal);

    emit_etw_msg(msg, pid);

    return g_origNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

NTSTATUS NTAPI Hook_NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    PVOID ClientId
)
{
    UINT64 tpid = 0;
    if (ClientId) {
        tpid = *(uintptr_t*)ClientId;

        char msg[64];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtOpenProcess with 0x%X", static_cast<unsigned int>(DesiredAccess));
        emit_etw_msg(msg, tpid);
    }

    // Call original
    return g_origNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS NTAPI Hook_NtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
)
{
    DWORD tpid = GetProcessId(ProcessHandle);
    uintptr_t addr = reinterpret_cast<uintptr_t>(BaseAddress);
    char msg[128];
    _snprintf_s(msg, sizeof(msg), _TRUNCATE,
        "NtReadVirtualMemory %llu bytes at 0x%0*llx",
        static_cast<unsigned long long>(NumberOfBytesToRead),
        static_cast<int>(sizeof(uintptr_t) * 2),
        static_cast<unsigned long long>(addr));

    emit_etw_msg(msg, tpid);

    // Call original
    return g_origNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
}

NTSTATUS NTAPI Hook_NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
)
{
    DWORD tpid = GetProcessId(ProcessHandle);
    uintptr_t addr = reinterpret_cast<uintptr_t>(BaseAddress);
    char msg[128];
    _snprintf_s(msg, sizeof(msg), _TRUNCATE,
        "NtWriteVirtualMemory %llu bytes at 0x%0*llx",
        static_cast<unsigned long long>(NumberOfBytesToWrite),
        static_cast<int>(sizeof(uintptr_t) * 2),
        static_cast<unsigned long long>(addr));

    emit_etw_msg(msg, tpid);

    // Call original
    return g_origNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

NTSTATUS NTAPI Hook_NtClose(HANDLE Handle)
{
    DWORD tpid = GetProcessId(Handle);
    if (tpid != 0) { // ignore closing events of non proc handles
        emit_etw_msg("NtClose process", tpid);
    }
    return g_origNtClose(Handle);
}

NTSTATUS NTAPI Hook_NtTerminateProcess(HANDLE Handle, NTSTATUS ExitStatus)
{
    DWORD tpid = GetProcessId(Handle);
    if (tpid != 0) { // ignore closing events of non proc handles 
        char msg[128];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
            "NtTerminateProcess with status 0x%lx",
            static_cast<LONG>(ExitStatus));
        emit_etw_msg(msg, tpid);
    }
    return g_origNtTerminateProcess(Handle, ExitStatus);
}


void InstallHooks()
{
    std::cout << "[+] Hook-DLL: Installing hooks...\n";

    // MinHook init
    if (MH_Initialize() != MH_OK) {
        emit_etw_error("MinHook init failed");
        return;
    }

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        emit_etw_error("ntdll not loaded");
        return;
    }

    // all functions to hook
    std::map<std::string, std::pair<void*, void**>> funcs = {
        {"NtOpenFile", {(void*)Hook_NtOpenFile, (void**)&g_origNtOpenFile}},
        {"NtReadFile", {(void*)Hook_NtReadFile, (void**)&g_origNtReadFile}},
        {"NtOpenProcess", {(void*)Hook_NtOpenProcess, (void**)&g_origNtOpenProcess}},
        {"NtReadVirtualMemory", {(void*)Hook_NtReadVirtualMemory, (void**)&g_origNtReadVirtualMemory}},
        {"NtWriteVirtualMemory", {(void*)Hook_NtWriteVirtualMemory, (void**)&g_origNtWriteVirtualMemory}},
        {"NtClose", {(void*)Hook_NtClose, (void**)&g_origNtClose}},
        {"NtTerminateProcess", {(void*)Hook_NtTerminateProcess, (void**)&g_origNtTerminateProcess}}
    };

    for (auto& it : funcs) {
        std::string name = it.first;
        std::pair<void*, void**> fn = it.second;
        FARPROC target = GetProcAddress(hNtdll, name.c_str());
        if (!target) {
            emit_etw_error(name + " not found in ntdll");
            continue;
        }

        if (MH_CreateHook(target, fn.first, (LPVOID*)fn.second) != MH_OK || MH_EnableHook(target) != MH_OK) {
            emit_etw_error("Failed to hook " + name);
        }
        else {
            emit_etw_ok("Hooked " + name);
        }
    }
    emit_etw_ok("++ NTDLL-HOOKER STARTED ++");
}

void RemoveHooks()
{
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
}

DWORD WINAPI t_InitHooks(LPVOID param)
{
    std::cout << "[+] Hook-DLL: Executing init thread...\n";
    TraceLoggingRegister(g_hProvider);
    pid = GetCurrentProcessId();
    InstallHooks();
    return 0;
}

DWORD WINAPI t_selfUnloadThread(LPVOID hinst) {
    Sleep(2000); // give the loader time to release the lock
    FreeLibraryAndExitThread((HMODULE)hinst, 0);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
    {
        //DisableThreadLibraryCalls(hinst);
        HANDLE hTread = CreateThread(nullptr, 0, t_InitHooks, nullptr, 0, nullptr);
        if (!hTread) {
            std::cerr << "[!] Hook-DLL: Failed to create init thread\n";
            return FALSE;
        }
        std::cout << "[+] Hook-DLL: Created init thread\n";
        break;
    }
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        //RemoveHooks();
        //TraceLoggingUnregister(g_hProvider);
        break;
    }
    return TRUE;
}