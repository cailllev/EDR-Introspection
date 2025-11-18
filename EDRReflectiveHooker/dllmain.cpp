#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <psapi.h>
#include <tchar.h>
#include <iostream>
#include <map>
#include <stdio.h>
#include <stdint.h>
#include <string>
#include <chrono>

#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <fstream>
#include <sddl.h>

#include <MinHook.h>
#include <TraceLoggingProvider.h>

#pragma intrinsic(_ReturnAddress)

/*
* Things NOT to do when injecting reflectively (can crash the loader in t_InitHooks):
* 
* - global std::vectors modified in hooked functions
* - large __try __except blocks (code inside these blocks can easily crash the loader)
* - convoluted code flow (i.e. many declarations, if statements, ...)
* - max 31 strings, like "abcd" in strcat(out, sizeof(out), "abcd") in one function
* - too many strings in A SINGLE SWITCH STATEMENT ??
* - char[size_to_big] can break loading sometimes ??
* - not using an allocated char[small_size] ??
* - == vs & in comparisions ??
* - ? changing to much code at once ?
* - ? breathing at the compiled DLL ?
* 
* Hints for debugging:
* - change one thing at a time, test it
* - if something breaks, comment out the things above until it works again
* - it can be very unintuitive what breaks the loader, try to really uncomment everything even if it seems unrelated
*/

// ------------------ REFL INJ ------------------ //
// from https://github.com/Reijaff/offensive_c/blob/main/dll_reflective_loader_64.c
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

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    PVOID Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    WORD Flags;
    WORD Length;
    ULONG TimeStamp;
    ANSI_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

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
    PLIST_ENTRY Head = &Peb->Ldr->InMemoryOrderModuleList;
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
static HANDLE H_PROC = NULL; // GetCurrentProcess() can be buggy after hooks installed
static UINT64 PID = 0; // GetCurrentProcessId() can be buggy after hooks installed

TRACELOGGING_DEFINE_PROVIDER(
    g_hProvider,
    "Hook-Provider", // name in the ETW, cannot be a variable
    (0x72248411, 0x7166, 0x4feb, 0xa3, 0x86, 0x34, 0xd8, 0xf3, 0x5b, 0xb6, 0x37)  // this cannot be a variable
);

// helper functions to combat recursion (GetCurrentProcessId -> NtQueryInformationProcess -> GetCurrentProcessId -> ...)
typedef NTSTATUS(NTAPI* PFN_GetCurrentProcessId)();

// hooked function definitions
typedef NTSTATUS (NTAPI* PFN_NtCreateFile)(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength
    );

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

typedef NTSTATUS(NTAPI* PFN_NtQueryInformationProcess)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
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

typedef NTSTATUS(NTAPI* PFN_NtSuspendProcess)(
    HANDLE Handle
    );

typedef NTSTATUS(NTAPI* PFN_NtResumeProcess)(
    HANDLE Handle
    );

typedef NTSTATUS(NTAPI* PFN_NtClose)(
    HANDLE Handle
    );

typedef NTSTATUS(NTAPI* PFN_NtTerminateProcess)(
    HANDLE   ProcessHandle,
    NTSTATUS ExitStatus
    );

// helper functions to minimize calls (GetCurrentProcessId -> NtQueryInformationProcess -> ... -> )
static PFN_GetCurrentProcessId g_origGetCurrentProcessId = nullptr;

// trampolines created by MinHook
static PFN_NtCreateFile g_origNtCreateFile = nullptr;
static PFN_NtOpenFile g_origNtOpenFile = nullptr;
static PFN_NtReadFile g_origNtReadFile = nullptr;
static PFN_NtOpenProcess g_origNtOpenProcess = nullptr;
static PFN_NtQueryInformationProcess g_origNtQueryInformationProcess = nullptr;
static PFN_NtReadVirtualMemory g_origNtReadVirtualMemory = nullptr;
static PFN_NtWriteVirtualMemory g_origNtWriteVirtualMemory = nullptr;
static PFN_NtSuspendProcess g_origNtSuspendProcess = nullptr;
static PFN_NtResumeProcess g_origNtResumeProcess = nullptr;
static PFN_NtClose g_origNtClose = nullptr;
static PFN_NtTerminateProcess g_origNtTerminateProcess = nullptr;

struct HookInfo {
    const char* name;
    void* hook;
    void** original;
};

UINT64 get_ns_time() {
    /*
    ChronoVsFiletime.exe:
    [*] Timing 1000000000 calls each...
    5.59516 ns per call - GetSystemTimeAsFileTime
    26.9772 ns per call - GetSystemTimePreciseAsFileTime
    23.9806 ns per call - chrono::system_clock::now()
    */
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
}

void emit_etw_ok(std::string msg) {
    UINT64 ns = get_ns_time();
    TraceLoggingWrite(
        g_hProvider,
        "HookTask", // the first event name is used for all events, unless using a manifest file
        TraceLoggingString(msg.c_str(), "message"),
        TraceLoggingUInt64(ns, "ns_since_epoch"),
        TraceLoggingUInt64(PID, "targetpid")
    );
    std::cout << "[+] Hook-DLL: " << msg << "\n";
};

void emit_etw_error(std::string error) {
    UINT64 ns = get_ns_time();
    TraceLoggingWrite(
        g_hProvider,
        "HookError",
        TraceLoggingString(error.c_str(), "message"),
        TraceLoggingUInt64(ns, "ns_since_epoch"),
        TraceLoggingUInt64(PID, "targetpid")
    );
    std::cerr << "[!] Hook-DLL: " << error << "\n";
};

void emit_etw_msg_ns(const char msg[], UINT64 tpid, UINT64 ns) {
    TraceLoggingWrite(
        g_hProvider,
        "HookTask",
        TraceLoggingString(msg, "message"),
        TraceLoggingUInt64(ns, "ns_since_epoch"),
        TraceLoggingUInt64(tpid, "targetpid")
    );
};

const size_t MISC_LEN = 128;
const size_t MSG_LEN = 1024;

// -------- UN-RECURSION LOGIC -------- //

// when hooking NtQueryInformationProcess, GetProcessId is also affected
DWORD UnhookedGetProcessId(HANDLE hProcess) {
    if (hProcess == NULL) return 0; // do NOT check for INVALID_HANDLE_VALUE, it's valid: https://devblogs.microsoft.com/oldnewthing/20230914-00/?p=108766

    PROCESS_BASIC_INFORMATION pbi;
    ULONG retLen;

    NTSTATUS status = g_origNtQueryInformationProcess(hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &retLen);

    if (status < 0) return 0; // handle not a process

    return (DWORD)(ULONG_PTR)pbi.UniqueProcessId;
}

// avoid recursion for GetCurrentProcessId calls
DWORD WINAPI Hook_GetCurrentProcessId() {
    return PID;
}

// ------- RESOLVER THREAD STRUCTS ------- //

// helper structure for ReadFile handle resolving
typedef struct _FNQ_ARGS {
    HANDLE           hProcess; // duplicated handle (or NULL on failure)
    PROCESSINFOCLASS pic;
    UINT64           Timestamp;
} FNQ_ARGS, * PFNQ_ARGS;

// helper structure for ReadFile handle resolving
typedef struct _FNF_ARGS {
    HANDLE FileHandle; // duplicated handle (or NULL on failure)
    UINT64 Timestamp;
} FNF_ARGS, * PFNF_ARGS;

// helper structure for ReadMemory offset resolving
typedef struct _FNM_ARGS {
    DWORD     tpid; // the process where the memory is read
    HANDLE    hProcess; // duplicated handle to the process (INVALID_HANDLE_VALUE is valid!)
    uintptr_t Offset; // the absolute memory offset
    SIZE_T    NumberOfBytesToRead;
    UINT64    Timestamp;
} FNM_ARGS, * PFNM_ARGS;

struct ProcessSection {
    DWORD pid;
    UINT64 allocBase;
    UINT64 sectionSize;
    char sectionName[MAX_PATH];
    char source[MAX_PATH];
};

struct ResolverTask {
    LPTHREAD_START_ROUTINE func; // ReadMemoryResolverThread or ReadFileResolverThread
    LPVOID arg;                  // argument struct pointer (FNM_ARGS* or FNF_ARGS*)
};

// ------- RESOLVER THREAD LOGIC ------- //
std::queue<ResolverTask> g_taskQueue;
std::mutex g_queueMutex;
std::condition_variable g_cv;
std::vector<std::thread> g_workers;
bool g_requestedStop = false;
int MAX_QUEUE_SIZE = 65536; // arbitrary

void ResolverWorker() {
    while (true) {
        ResolverTask task;

        {
            std::unique_lock<std::mutex> lock(g_queueMutex);
            g_cv.wait(lock, [] { 
                return g_requestedStop || !g_taskQueue.empty(); 
            });

            if (g_requestedStop && g_taskQueue.empty())
                return; // clean exit

            task = g_taskQueue.front();
            g_taskQueue.pop();
        }

        if (task.func && task.arg)
            task.func(task.arg);
    }
}

void InitResolverPool(int numThreads) {
    for (int i = 0; i < numThreads; i++) {
        g_workers.emplace_back(ResolverWorker);
    }
}

void StopResolverPool() {
    {
        std::lock_guard<std::mutex> lock(g_queueMutex);
        g_requestedStop = true;
    }
    g_cv.notify_all();

    for (auto& t : g_workers)
        t.join();
}

bool EnqueueResolverTask(LPTHREAD_START_ROUTINE func, LPVOID arg) {
    std::unique_lock<std::mutex> lock(g_queueMutex);
    if (g_taskQueue.size() >= MAX_QUEUE_SIZE) {
        lock.unlock();
        return false;
    }
    g_taskQueue.push(ResolverTask{ func, arg });
    lock.unlock();
    g_cv.notify_one();
    return true;
}

// worker thread: resolve procinfo and emit ETW
DWORD WINAPI ReadProcInfoResolverThread(LPVOID lpParam)
{
    FNQ_ARGS* args = (FNQ_ARGS*)lpParam;
    if (!args) return 0;
    HANDLE hProcess = args->hProcess;
	PROCESSINFOCLASS pic = args->pic;
    UINT64 ns = args->Timestamp;

    char msg[MSG_LEN] = { 0 };
    char infoClass[MISC_LEN] = { 0 };

    DWORD tpid = UnhookedGetProcessId(hProcess);

    // https://ntdoc.m417z.com/processinfoclass
    if (pic == 0x0) {
        _snprintf_s(infoClass, sizeof(infoClass), _TRUNCATE, "ProcessBasicInformation");
    }
    else if (pic == 0x4) {
        _snprintf_s(infoClass, sizeof(infoClass), _TRUNCATE, "ProcessSessionInformation");
    }
    else if (pic == 0x17) {
        _snprintf_s(infoClass, sizeof(infoClass), _TRUNCATE, "ProcessDeviceMap");
    }
    else if (pic == 0x18) {
        _snprintf_s(infoClass, sizeof(infoClass), _TRUNCATE, "ThreadPagePriority");
    }
    else if (pic == 0x1A) {
        _snprintf_s(infoClass, sizeof(infoClass), _TRUNCATE, "ProcessWow64Information");
    }
    else if (pic == 0x1B) {
        _snprintf_s(infoClass, sizeof(infoClass), _TRUNCATE, "ProcessImageFileName");
    }
    else if (pic == 0x25) {
        _snprintf_s(infoClass, sizeof(infoClass), _TRUNCATE, "ProcessImageInformation");
    }
    else if (pic == 0x3C) {
        _snprintf_s(infoClass, sizeof(infoClass), _TRUNCATE, "ProcessCommandLineInformation");
    }
    else if (pic == 0x60) {
        _snprintf_s(infoClass, sizeof(infoClass), _TRUNCATE, "ProcessLoggingInformation");
	}
    else {
        _snprintf_s(infoClass, sizeof(infoClass), _TRUNCATE, "0x%X", pic);
    }

    _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtQueryInformationProcess with InfoClass=%s", infoClass);

    emit_etw_msg_ns(msg, tpid, ns);

    if (hProcess && hProcess != INVALID_HANDLE_VALUE) g_origNtClose(hProcess);
    free(args);
    return 0;
}

// worker thread: resolve filename and emit ETW
DWORD WINAPI ReadFileResolverThread(LPVOID lpParam)
{
    FNF_ARGS* args = (FNF_ARGS*)lpParam;
    if (!args) return 0;
    HANDLE hFile = args->FileHandle;
    UINT64 ns = args->Timestamp;

    char msg[MSG_LEN] = { 0 };
    
    if (!hFile || hFile == INVALID_HANDLE_VALUE) { // default message if invalid handle
        _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtReadFile handle=0x%p (invalid handle)", (void*)hFile);
    }
    else {
        DWORD maxLen = MAX_PATH + 1;
        char* buf = (char*)malloc(maxLen);
        if (buf) {
            __try {
                if (GetFinalPathNameByHandleA(hFile, buf, maxLen, FILE_NAME_NORMALIZED)) {
                    _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtReadFile %s", buf);
                }
                else {
                    _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtReadFile handle=0x%p (resolve failed)", (void*)hFile);
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtReadFile handle=0x%p (GetFinalPathNameByHandleA exception)", (void*)hFile);
			}
            free(buf);
        }
        else {
            _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtReadFile handle=0x%p (alloc failed)", (void*)hFile);
        }
    }

    emit_etw_msg_ns(msg, PID, ns);

    if (hFile && hFile != INVALID_HANDLE_VALUE) g_origNtClose(hFile);
    free(args);
    return 0;
}

// Resolve a given memory offset in a process to an image / region (private, ...) 
DWORD WINAPI ReadMemoryResolverThread(LPVOID lpParam) {
    FNM_ARGS* args = (FNM_ARGS*)lpParam;
    if (!args) return 0;

    if (g_origNtQueryInformationProcess == nullptr || g_origNtReadVirtualMemory == nullptr) {
        free(args);
        return 0;
    }

    DWORD tpid = args->tpid;
    HANDLE hProcess = args->hProcess;
    uintptr_t offset = args->Offset;
    SIZE_T bytesToRead = args->NumberOfBytesToRead;
    UINT64 ns = args->Timestamp;

    char msg[MSG_LEN] = { 0 };
    char error[MISC_LEN] = { 0 };
    char vqeError[MISC_LEN] = { 0 };
    char combinedError[MISC_LEN] = { 0 };
    bool err = false;
    bool found = false;

    ProcessSection section = ProcessSection{ 0, 0, 0, "Unknown", "" };

    // DO NOT use INVALID_PROCESS_HANDLE here, INVALID_PROCESS_HANDLE (-1) is ACTUALLY USED for same process reads
    if (hProcess == NULL) {
        _snprintf_s(combinedError, sizeof(combinedError), _TRUNCATE, ", Handle error: hProcess is NULL");
    }

    else {
        if (!found) { // offset currently unknown

            // ------------- RESOLVE IMAGE SECTIONS (EXE + DLL) ------------- //
            // from https://github.com/dobin/RedEdr/blob/master/RedEdrShared/process_query.cpp

            PROCESS_BASIC_INFORMATION pbi = {};
            ULONG returnLength;

            // PBI
            if (!err && g_origNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength) != 0) {
                _snprintf_s(error, sizeof(error), _TRUNCATE, "Could not NtQueryInformationProcess for %p error=%lu", hProcess, GetLastError());
                err = true;
            }
            if (!err && pbi.PebBaseAddress == 0) {
                _snprintf_s(error, sizeof(error), _TRUNCATE, "pbi.PebBaseAddress is NULL");
                err = true;
            }

            // PEB, read into local PEB
            SIZE_T bytesRead = 0;
            PEB peb = { 0 };
            if (!err && g_origNtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead) != 0) {
                _snprintf_s(error, sizeof(error), _TRUNCATE, "Could not read PEB error=%lu", GetLastError());
                err = true;
            }
            if (!err && !peb.Ldr) {
                _snprintf_s(error, sizeof(error), _TRUNCATE, "PEB.Ldr is NULL");
                err = true;
            }

            if (!err) {
                // remote pointer to PEB_LDR_DATA
                PBYTE remoteLdrAddr = (PBYTE)peb.Ldr;

                // read remote PEB_LDR_DATA into local ldr
                PEB_LDR_DATA ldr = { 0 };
                if (g_origNtReadVirtualMemory(hProcess, remoteLdrAddr, &ldr, sizeof(ldr), &bytesRead) != 0) {
                    _snprintf_s(error, sizeof(error), _TRUNCATE, "ReadProcessMemory failed for PEB_LDR_DATA error=%lu", GetLastError());
                    err = true;
                }

                // compute remote head address (remote address of the LIST_ENTRY inside the remote PEB_LDR_DATA)
                PBYTE remoteHead = remoteLdrAddr + offsetof(PEB_LDR_DATA, InMemoryOrderModuleList);

                // start with the remote Flink (this is a remote pointer)
                LIST_ENTRY remoteList = ldr.InMemoryOrderModuleList;
                PVOID current = remoteList.Flink; // remote address

                // alloc memory locally for name
                int maxLen = (MAX_PATH + 1) * sizeof(WCHAR);
                WCHAR* localNameW = (WCHAR*)malloc(maxLen);
                if (!localNameW) {
                    _snprintf_s(error, sizeof(error), _TRUNCATE, "Unable to alloc memory for local name");
                    err = true;
                }

                int maxIterations = 1000;
                int iter = 0;

                // enumerate all remote memory regions (silently ignore errors here)
                while (current && (PBYTE)current != remoteHead && iter < maxIterations) {
                    // remote address of the containing LDR_DATA_TABLE_ENTRY
                    PBYTE remoteEntryAddr = (PBYTE)current - offsetof(_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

                    _LDR_DATA_TABLE_ENTRY entry;
                    ZeroMemory(&entry, sizeof(entry));
                    if (g_origNtReadVirtualMemory(hProcess, remoteEntryAddr, &entry, sizeof(entry), &bytesRead) != 0) {
                        //_snprintf_s(error, sizeof(error), _TRUNCATE, "RPM failed for LDR entry at 0x%p. Error: %lu\n", remoteEntryAddr, GetLastError());
                        current = entry.InMemoryOrderLinks.Flink;
                        iter++; continue;
                    }

                    if (entry.DllBase == NULL) { // end marker (or corrupted block)
                        break;
                    }

                    // check FullDllName fields
                    USHORT nameLen = entry.FullDllName.Length;
                    if (!entry.FullDllName.Buffer || !nameLen || nameLen < 0 || nameLen > 0x2000) {
                        current = entry.InMemoryOrderLinks.Flink;
                        iter++; continue;
                    }

                    // Read the remote FullDllName.Buffer into a local wchar buffer
                    ZeroMemory(localNameW, maxLen);
                    if (g_origNtReadVirtualMemory(hProcess, entry.FullDllName.Buffer, localNameW, nameLen, &bytesRead) == 0) {
                        uint64_t base = reinterpret_cast<uint64_t>(entry.DllBase);
                        uint64_t size = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(entry.Reserved3[1]));

                        // check if offset from loaded image is in this section
                        if (offset >= base && offset < base + size) {
                            section.pid = tpid;
                            section.allocBase = base;
                            section.sectionSize = size;

                            // read dll name
                            size_t wcharCount = (nameLen / sizeof(WCHAR));
                            localNameW[wcharCount] = L'\0';
                            char nameBuf[MAX_PATH];
                            WideCharToMultiByte(CP_ACP, 0, localNameW, -1, nameBuf, sizeof(nameBuf), NULL, NULL);
                            _snprintf_s(section.sectionName, sizeof(section.sectionName), _TRUNCATE, nameBuf);
                            _snprintf_s(section.source, sizeof(section.source), _TRUNCATE, "(PEB) ");

                            found = true;
                            break;
                        }
                    }

                    // advance to next remote entry
                    current = entry.InMemoryOrderLinks.Flink;
                    iter++;
                }
                free(localNameW);
            }
        }

        if (!found) { // offset still unknown

            // ------------- RESOLVE PROC MEMORY SECTIONS ------------- //

            MEMORY_BASIC_INFORMATION mbi = { 0 };
            if (VirtualQueryEx(hProcess, (LPCVOID)offset, &mbi, sizeof(mbi)) == sizeof(mbi)) {

                section.pid = tpid;
                section.allocBase = (UINT64)mbi.AllocationBase; // this is a per process base
                section.sectionSize = (UINT64)mbi.RegionSize;
                
                // get the mapped file name if it's a MEM_IMAGE or MEM_MAPPED
                if (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED) {
                    _snprintf_s(section.source, sizeof(section.source), _TRUNCATE, "(ManualMap) "); // normal mapping of images would be detected by PEB walk
                    WCHAR wName[MAX_PATH];
                    if (GetMappedFileNameW(hProcess, mbi.BaseAddress, wName, MAX_PATH)) {
                        WideCharToMultiByte(CP_ACP, 0, wName, -1, section.sectionName, MAX_PATH, NULL, NULL);
                    }
                    else {
                        strncpy_s(section.sectionName, "ImageOrMappedNoName", _TRUNCATE);
                    }
                }
                else { // else store the memory type
                    _snprintf_s(section.source, sizeof(section.source), _TRUNCATE, "(NoImage) ");
                    if (mbi.Type == MEM_PRIVATE) {
                        _snprintf_s(section.sectionName, sizeof(section.sectionName), _TRUNCATE, "Private");
                    }
                    else {
                        _snprintf_s(section.sectionName, sizeof(section.sectionName), _TRUNCATE, "UnknownMemType_0x%lx", mbi.Type);
                    }
                }
                found = true; // irrelevant after here
            }
            else {
                _snprintf_s(vqeError, sizeof(vqeError), _TRUNCATE, "mbi is NULL");
            }
        }
    }

    // Combine errors for logging
    if (strlen(error) > 0) {
        _snprintf_s(combinedError, sizeof(combinedError), _TRUNCATE, ", QueryInfoProc error: %s", error);
    }
    if (strlen(vqeError) > 0) {
        size_t len = strlen(combinedError);
        _snprintf_s(combinedError + len, sizeof(combinedError) - len, _TRUNCATE, ", VirtualQuery error: %s", vqeError);
    }

    _snprintf_s(msg, sizeof(msg), _TRUNCATE,
        "NtReadVirtualMemory 0x%llx bytes from %s%s!0x%0*llx%s",
        static_cast<unsigned long long>(bytesToRead),
        section.source,
        section.sectionName,
        static_cast<int>(sizeof(uintptr_t) * 2),
        static_cast<unsigned long long>(offset),
        combinedError);
    emit_etw_msg_ns(msg, tpid, ns);

    if (hProcess) g_origNtClose(hProcess);
    free(args);
    return 0;
}


NTSTATUS NTAPI Hook_NtQueryInformationProcess(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
) {
    UINT64 ns = get_ns_time();
    NTSTATUS ret = g_origNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

    char msg[MSG_LEN] = { 0 };

    // duplicate handle to ensure validity in worker thread
    HANDLE dup = NULL;
    BOOL ok = DuplicateHandle(
        H_PROC, ProcessHandle,
        H_PROC, &dup,
        0, FALSE, DUPLICATE_SAME_ACCESS
    );
    if (!ok) {
        if (dup) g_origNtClose(dup);
        _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtQueryInformationProcess handle=0x%p (error %lu duplicating handle)", (void*)dup, GetLastError());
        emit_etw_msg_ns(msg, PID, ns);
        return ret;
    }

    // prepare args: dup may be NULL on failure; worker will handle it
    FNQ_ARGS* args = (FNQ_ARGS*)malloc(sizeof(FNQ_ARGS));
    if (args) {
        args->hProcess = dup;
        args->pic = ProcessInformationClass;
        args->Timestamp = ns;
        if (!EnqueueResolverTask(ReadProcInfoResolverThread, args)) {
            _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtQueryInformationProcess handle=0x%p (resolver queue limit reached)", (void*)dup);
            emit_etw_msg_ns(msg, PID, ns);
            free(args);
        }
    }
    else { // allocation failed: cleanup duplicate
        if (dup) g_origNtClose(dup);
    }

    return ret;
}

NTSTATUS NTAPI Hook_NtCreateFile(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength
) {
    UINT64 ns = get_ns_time();

    char msg[MSG_LEN] = { 0 };
    char accFlags[MISC_LEN * 4] = { 0 }; // need space
    char accDesc[MISC_LEN * 4] = { 0 }; // need space
    char dispo[MISC_LEN] = { 0 };

    // basic file access masks
    if (DesiredAccess & FILE_READ_DATA) {
        strcat_s(accFlags, sizeof(accFlags), "FILE_READ_DATA|");
    }
    if (DesiredAccess & FILE_WRITE_DATA) {
        strcat_s(accFlags, sizeof(accFlags), "FILE_WRITE_DATA|");
    }
    if (DesiredAccess & FILE_APPEND_DATA) {
        strcat_s(accFlags, sizeof(accFlags), "FILE_APPEND_DATA|");
    }
    if (DesiredAccess & FILE_READ_EA) {
        strcat_s(accFlags, sizeof(accFlags), "FILE_READ_EA|");
    }
    if (DesiredAccess & FILE_WRITE_EA) {
        strcat_s(accFlags, sizeof(accFlags), "FILE_WRITE_EA|");
    }
    if (DesiredAccess & FILE_EXECUTE) {
        strcat_s(accFlags, sizeof(accFlags), "FILE_EXECUTE|");
    }
    if (DesiredAccess & FILE_DELETE_CHILD) {
        strcat_s(accFlags, sizeof(accFlags), "FILE_DELETE_CHILD|");
    }
    if (DesiredAccess & FILE_READ_ATTRIBUTES) {
        strcat_s(accFlags, sizeof(accFlags), "FILE_READ_ATTRIBUTES|");
    }
    if (DesiredAccess & FILE_WRITE_ATTRIBUTES) {
        strcat_s(accFlags, sizeof(accFlags), "FILE_WRITE_ATTRIBUTES|");
    }
    // access types
    if (DesiredAccess & DELETE) {
        strcat_s(accFlags, sizeof(accFlags), "DELETE|");
    }
    if (DesiredAccess & READ_CONTROL) {
        strcat_s(accFlags, sizeof(accFlags), "READ_CONTROL|");
    }
    if (DesiredAccess & WRITE_DAC) {
        strcat_s(accFlags, sizeof(accFlags), "WRITE_DAC|");
    }
    if (DesiredAccess & WRITE_OWNER) {
        strcat_s(accFlags, sizeof(accFlags), "WRITE_OWNER|");
    }
    if (DesiredAccess & SYNCHRONIZE) {
        strcat_s(accFlags, sizeof(accFlags), "SYNCHRONIZE|");
    }
    // generic access
    if (DesiredAccess & GENERIC_EXECUTE) {
        strcat_s(accFlags, sizeof(accFlags), "GENERIC_EXECUTE|");
    }
    if (DesiredAccess & GENERIC_WRITE) {
        strcat_s(accFlags, sizeof(accFlags), "GENERIC_WRITE|");
    }
    if (DesiredAccess & GENERIC_READ) {
        strcat_s(accFlags, sizeof(accFlags), "GENERIC_READ|");
    }
    if (DesiredAccess & GENERIC_ALL) {
        strcat_s(accFlags, sizeof(accFlags), "GENERIC_ALL|");
    }
    // remove trailing |
    size_t len = strlen(accFlags);
    if (len > 0 && accFlags[len - 1] == '|') {
        accFlags[len - 1] = '\0';
    }
    _snprintf_s(accDesc, sizeof(accDesc), _TRUNCATE, "0x%X:%s", (unsigned)DesiredAccess, accFlags);

    switch (CreateDisposition) {
    case FILE_SUPERSEDE: _snprintf_s(dispo, sizeof(dispo), _TRUNCATE, "replace or create if not exists"); break;
    case FILE_CREATE: _snprintf_s(dispo, sizeof(dispo), _TRUNCATE, "create or fail if exists"); break;
    case FILE_OPEN: _snprintf_s(dispo, sizeof(dispo), _TRUNCATE, "open or fail if not exists"); break;
    case FILE_OPEN_IF: _snprintf_s(dispo, sizeof(dispo), _TRUNCATE, "open or create if not exists"); break;
    case FILE_OVERWRITE: _snprintf_s(dispo, sizeof(dispo), _TRUNCATE, "overwrite or fail if not exists"); break;
    case FILE_OVERWRITE_IF: _snprintf_s(dispo, sizeof(dispo), _TRUNCATE, "overwrite or create if not exists"); break;
    default: _snprintf_s(dispo, sizeof(dispo), _TRUNCATE, "unknown-flag:0x%lX", CreateDisposition); break;
    }

    if (ObjectAttributes && ObjectAttributes->ObjectName) {
        
        PUNICODE_STRING name = ObjectAttributes->ObjectName;
        if (name->Buffer && name->Length > 0) {

            char nameBuf[MAX_PATH] = { 0 };

            int wcharCount = (int)(name->Length / sizeof(WCHAR));
            if (wcharCount > (MAX_PATH - 1))
                wcharCount = MAX_PATH - 1;

            WideCharToMultiByte(CP_ACP, 0, name->Buffer, wcharCount, nameBuf, MAX_PATH - 1, NULL, NULL);
            nameBuf[MAX_PATH - 1] = '\0'; // ensure termination
            _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtCreateFile %s with DesiredAccess=%s and Disposition='%s'", nameBuf, accDesc, dispo);

            // this try / except breaks the reflective loading, YOLO
            /*
            __try {
                WideCharToMultiByte(CP_ACP, 0, name->Buffer, wcharCount, nameBuf, MAX_PATH - 1, NULL, NULL);
                nameBuf[MAX_PATH - 1] = '\0'; // ensure termination
                _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtCreateFile %s with DesiredAccess=%s and Disposition='%s'", nameBuf, acc, dispo);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtCreateFile (invalid ObjectName pointer) with DesiredAccess=%s and Disposition='%s'", acc, dispo);
            }
            */
        }
        else {
            _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtCreateFile (no or invalid name) with DesiredAccess=%s and Disposition='%s'", accDesc, dispo);
        }
    }
    else {
        _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtCreateFile (no objectattrs) with DesiredAccess=%s and Disposition='%s'", accDesc, dispo);
    }

    emit_etw_msg_ns(msg, PID, ns);

    return g_origNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

NTSTATUS NTAPI Hook_NtOpenFile(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    ULONG              ShareAccess,
    ULONG              OpenOptions
) {
	UINT64 ns = get_ns_time();

    char msg[MSG_LEN] = { 0 };
    char accFlags[MISC_LEN * 4] = { 0 }; // need space
    char accDesc[MISC_LEN * 4] = { 0 }; // need space

    // basic file access masks
    if (DesiredAccess & FILE_READ_DATA) {
        strcat_s(accFlags, sizeof(accFlags), "FILE_READ_DATA|");
    }
    if (DesiredAccess & FILE_WRITE_DATA) {
        strcat_s(accFlags, sizeof(accFlags), "FILE_WRITE_DATA|");
    }
    if (DesiredAccess & FILE_APPEND_DATA) {
        strcat_s(accFlags, sizeof(accFlags), "FILE_APPEND_DATA|");
    }
    if (DesiredAccess & FILE_READ_EA) {
        strcat_s(accFlags, sizeof(accFlags), "FILE_READ_EA|");
    }
    if (DesiredAccess & FILE_WRITE_EA) {
        strcat_s(accFlags, sizeof(accFlags), "FILE_WRITE_EA|");
    }
    if (DesiredAccess & FILE_EXECUTE) {
        strcat_s(accFlags, sizeof(accFlags), "FILE_EXECUTE|");
    }
    if (DesiredAccess & FILE_DELETE_CHILD) {
        strcat_s(accFlags, sizeof(accFlags), "FILE_DELETE_CHILD|");
    }
    if (DesiredAccess & FILE_READ_ATTRIBUTES) {
        strcat_s(accFlags, sizeof(accFlags), "FILE_READ_ATTRIBUTES|");
    }
    if (DesiredAccess & FILE_WRITE_ATTRIBUTES) {
        strcat_s(accFlags, sizeof(accFlags), "FILE_WRITE_ATTRIBUTES|");
    }
    // access types
    if (DesiredAccess & DELETE) {
        strcat_s(accFlags, sizeof(accFlags), "DELETE|");
    }
    if (DesiredAccess & READ_CONTROL) {
        strcat_s(accFlags, sizeof(accFlags), "READ_CONTROL|");
    }
    if (DesiredAccess & WRITE_DAC) {
        strcat_s(accFlags, sizeof(accFlags), "WRITE_DAC|");
    }
    if (DesiredAccess & WRITE_OWNER) {
        strcat_s(accFlags, sizeof(accFlags), "WRITE_OWNER|");
    }
    if (DesiredAccess & SYNCHRONIZE) {
        strcat_s(accFlags, sizeof(accFlags), "SYNCHRONIZE|");
    }
    // generic access
    if (DesiredAccess & GENERIC_EXECUTE) {
        strcat_s(accFlags, sizeof(accFlags), "GENERIC_EXECUTE|");
    }
    if (DesiredAccess & GENERIC_WRITE) {
        strcat_s(accFlags, sizeof(accFlags), "GENERIC_WRITE|");
    }
    if (DesiredAccess & GENERIC_READ) {
        strcat_s(accFlags, sizeof(accFlags), "GENERIC_READ|");
    }
    if (DesiredAccess & GENERIC_ALL) {
        strcat_s(accFlags, sizeof(accFlags), "GENERIC_ALL|");
    }
    // remove trailing |
    size_t len = strlen(accFlags);
    if (len > 0 && accFlags[len - 1] == '|') {
        accFlags[len - 1] = '\0';
    }
    _snprintf_s(accDesc, sizeof(accDesc), _TRUNCATE, "0x%X:%s", (unsigned)DesiredAccess, accFlags);

    if (ObjectAttributes && ObjectAttributes->ObjectName) {

        PUNICODE_STRING name = ObjectAttributes->ObjectName;
        if (name->Buffer && name->Length > 0) {

            char nameBuf[MAX_PATH] = { 0 };

            int wcharCount = (int)(name->Length / sizeof(WCHAR));
            if (wcharCount > (MAX_PATH - 1))
                wcharCount = MAX_PATH - 1;

            __try {
                WideCharToMultiByte(CP_ACP, 0, name->Buffer, wcharCount, nameBuf, MAX_PATH - 1, NULL, NULL);
                nameBuf[MAX_PATH - 1] = '\0'; // ensure termination
                _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtOpenFile %s with DesiredAccess=%s", nameBuf, accDesc);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtOpenFile (invalid ObjectName pointer) with DesiredAccess=%s", accDesc);
            }
        }
        else {
            _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtOpenFile (no or invalid name) with DesiredAccess=%s", accDesc);
        }
    }
    else {
        _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtOpenFile (no objectattrs) with DesiredAccess=%s", accDesc);
    }
    emit_etw_msg_ns(msg, PID, ns);

    return g_origNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}

NTSTATUS NTAPI Hook_NtReadFile(
    HANDLE           FileHandle,
    HANDLE           Event,
    PIO_APC_ROUTINE  ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            Buffer,
    ULONG            Length,
    PLARGE_INTEGER   ByteOffset,
    PULONG           Key
) {
    UINT64 ns = get_ns_time();
    NTSTATUS ret = g_origNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);

    char msg[MSG_LEN] = { 0 };

    // duplicate handle to ensure validity in worker thread
    HANDLE dup = NULL;
    BOOL ok = false;
    if (FileHandle && FileHandle != INVALID_HANDLE_VALUE) {
        ok = DuplicateHandle(
            H_PROC, FileHandle,
            H_PROC, &dup,
            0, FALSE, DUPLICATE_SAME_ACCESS
        );
    }
    if (!ok) {
        if (dup) g_origNtClose(dup);
        _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtReadFile handle=0x%p (error %lu duplicating handle)", (void*)dup, GetLastError());
        emit_etw_msg_ns(msg, PID, ns);
        return ret;
    }

    // prepare args: dup may be NULL on failure; worker will handle it
    FNF_ARGS* args = (FNF_ARGS*)malloc(sizeof(FNF_ARGS));
    if (args) {
        args->FileHandle = dup;
        args->Timestamp = ns;
        if (!EnqueueResolverTask(ReadFileResolverThread, args)) {
            _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtReadFile handle=0x%p (resolver queue limit reached)", (void*)dup);
            emit_etw_msg_ns(msg, PID, ns);
            free(args);
        }
    }
    else { // allocation failed: cleanup duplicate
        if (dup) g_origNtClose(dup);
    }
    return ret;
}

NTSTATUS NTAPI Hook_NtOpenProcess(
    PHANDLE     ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PVOID       ObjectAttributes,
    PVOID       ClientId
)
{
    UINT64 ns = get_ns_time();
    UINT64 tpid = 0;
    if (ClientId) {
        tpid = *(uintptr_t*)ClientId;
    }

	char acc[MISC_LEN] = { 0 };

    if (DesiredAccess & PROCESS_TERMINATE) {
        strcat_s(acc, sizeof(acc), "PROCESS_TERMINATE|");
	}
    if (DesiredAccess & PROCESS_CREATE_THREAD) {
        strcat_s(acc, sizeof(acc), "PROCESS_CREATE_THREAD|");
	}
    if (DesiredAccess & PROCESS_VM_OPERATION) {
        strcat_s(acc, sizeof(acc), "PROCESS_VM_OPERATION|");
    }
    if (DesiredAccess & PROCESS_VM_READ) {
        strcat_s(acc, sizeof(acc), "PROCESS_VM_READ|");
    }
    if (DesiredAccess & PROCESS_VM_WRITE) {
        strcat_s(acc, sizeof(acc), "PROCESS_VM_WRITE|");
    }
    if (DesiredAccess & PROCESS_DUP_HANDLE) {
        strcat_s(acc, sizeof(acc), "PROCESS_DUP_HANDLE|");
    }
    if (DesiredAccess & PROCESS_CREATE_PROCESS) {
        strcat_s(acc, sizeof(acc), "PROCESS_CREATE_PROCESS|");
    }
    if (DesiredAccess & PROCESS_SET_QUOTA) {
        strcat_s(acc, sizeof(acc), "PROCESS_SET_QUOTA|");
    }
    if (DesiredAccess & PROCESS_SET_INFORMATION) {
        strcat_s(acc, sizeof(acc), "PROCESS_SET_INFORMATION|");
    }
    if (DesiredAccess & PROCESS_QUERY_INFORMATION) {
        strcat_s(acc, sizeof(acc), "PROCESS_QUERY_INFORMATION|");
    }
    if (DesiredAccess & PROCESS_SUSPEND_RESUME) {
        strcat_s(acc, sizeof(acc), "PROCESS_SUSPEND_RESUME|");
    }
    if (DesiredAccess & PROCESS_QUERY_LIMITED_INFORMATION) {
        strcat_s(acc, sizeof(acc), "PROCESS_QUERY_LIMITED_INFORMATION|");
    }
    if (DesiredAccess & PROCESS_SET_LIMITED_INFORMATION) {
        strcat_s(acc, sizeof(acc), "PROCESS_SET_LIMITED_INFORMATION|");
    }
    if (DesiredAccess & SYNCHRONIZE) {
        strcat_s(acc, sizeof(acc), "SYNCHRONIZE|");
    }

	size_t len = strlen(acc);
    if (len > 0) {
        acc[len - 1] = '\0'; // remove last '|'
    }

    char msg[MSG_LEN] = { 0 };
    _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtOpenProcess with 0x%X:%s", static_cast<unsigned int>(DesiredAccess), acc);

    emit_etw_msg_ns(msg, tpid, ns);
    return g_origNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS NTAPI Hook_NtReadVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
)
{
    UINT64 ns = get_ns_time();
    NTSTATUS ret = g_origNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);

    DWORD tpid = UnhookedGetProcessId(ProcessHandle);
    uintptr_t addr = reinterpret_cast<uintptr_t>(BaseAddress);

    char msg[MSG_LEN] = { 0 };

    // duplicate handle to ensure validity in worker thread
    HANDLE dup = NULL;
    BOOL ok = false;
    if (ProcessHandle != NULL) { // do not check for INVALID_HANDLE_VALUE: https://devblogs.microsoft.com/oldnewthing/20230914-00/?p=108766
        ok = DuplicateHandle(
            H_PROC, ProcessHandle,
            H_PROC, &dup,
            0, FALSE, DUPLICATE_SAME_ACCESS
        );
    }
    if (!ok) { // this is the only check needed if a handle is valid to use later
        if (dup) g_origNtClose(dup);
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
            "NtReadVirtualMemory 0x%llx bytes from Unknown!0x%0*llx, DuplicateHandle: error %lu duplicating handle",
            static_cast<unsigned long long>(NumberOfBytesToRead),
            static_cast<int>(sizeof(uintptr_t) * 2),
            static_cast<unsigned long long>(addr),
            GetLastError());
        emit_etw_msg_ns(msg, tpid, ns);
        return ret;
    }

    // prepare args and enqueue (args are freed in worker function normally)
    FNM_ARGS* args = (FNM_ARGS*)malloc(sizeof(FNM_ARGS));
    if (args) {
        args->tpid = tpid;
        args->hProcess = dup;
        args->Offset = addr;
        args->NumberOfBytesToRead = NumberOfBytesToRead;
        args->Timestamp = ns;
        if (!EnqueueResolverTask(ReadMemoryResolverThread, args)) {
            _snprintf_s(msg, sizeof(msg), _TRUNCATE,
                "NtReadVirtualMemory 0x%llx bytes from Unknown!0x%0*llx, Resolver: queue limit reached",
                static_cast<unsigned long long>(NumberOfBytesToRead),
                static_cast<int>(sizeof(uintptr_t) * 2),
                static_cast<unsigned long long>(addr));
            emit_etw_msg_ns(msg, PID, ns);
            free(args);
        }
    }
    else { // allocation failed: cleanup duplicate
        if (dup) g_origNtClose(dup);
    }
    return ret;
}

NTSTATUS NTAPI Hook_NtWriteVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
)
{
    UINT64 ns = get_ns_time();
    DWORD tpid = UnhookedGetProcessId(ProcessHandle);
    uintptr_t addr = reinterpret_cast<uintptr_t>(BaseAddress);

    char msg[MSG_LEN] = { 0 };
    _snprintf_s(msg, sizeof(msg), _TRUNCATE,
        "NtWriteVirtualMemory 0x%llx bytes at 0x%0*llx",
        static_cast<unsigned long long>(NumberOfBytesToWrite),
        static_cast<int>(sizeof(uintptr_t) * 2),
        static_cast<unsigned long long>(addr));

    emit_etw_msg_ns(msg, tpid, ns);
    return g_origNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

NTSTATUS NTAPI Hook_NtSuspendProcess(
    HANDLE Handle
) {
    UINT64 ns = get_ns_time();
    DWORD tpid = UnhookedGetProcessId(Handle);
    emit_etw_msg_ns("NtSuspendProcess", tpid, ns);
    return g_origNtSuspendProcess(Handle);
}

NTSTATUS NTAPI Hook_NtResumeProcess(
    HANDLE Handle
) {
    UINT64 ns = get_ns_time();
    DWORD tpid = UnhookedGetProcessId(Handle);
    emit_etw_msg_ns("NtResumeProcess", tpid, ns);
    return g_origNtResumeProcess(Handle);
}

NTSTATUS NTAPI Hook_NtClose(
    HANDLE Handle
) {
    UINT64 ns = get_ns_time();
    int tpid = (int)UnhookedGetProcessId(Handle); // can return garbage for non-process handles
    if (tpid >= 4 && tpid <= 0xFFFFFF) { // ignore closing events of non proc handles
        emit_etw_msg_ns("NtClose process", tpid, ns);
    }
    return g_origNtClose(Handle);
}

NTSTATUS NTAPI Hook_NtTerminateProcess(
    HANDLE   Handle, 
    NTSTATUS ExitStatus
) {
    UINT64 ns = get_ns_time();
    char msg[MSG_LEN] = { 0 };

	int tpid = (int)UnhookedGetProcessId(Handle); // can return garbage for non-process handles
    if (tpid >= 4 && tpid <= 0xFFFFFF) { // ignore closing events of non proc handles
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
            "NtTerminateProcess with status 0x%lx",
            static_cast<LONG>(ExitStatus));
        emit_etw_msg_ns(msg, tpid, ns);
    }
    return g_origNtTerminateProcess(Handle, ExitStatus);
}

// -------- HOOKING FRAMEWORK SETUP, STARTUP, TEARDOWN -------- //
typedef enum _EVENT_TYPE {
    NotificationEvent = 0,
    SynchronizationEvent = 1
} EVENT_TYPE;

typedef NTSTATUS(NTAPI* PFN_NtCreateEvent)(
    PHANDLE            EventHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    EVENT_TYPE         EventType,
    BOOLEAN            InitialState
    );
typedef NTSTATUS(NTAPI* PFN_NtOpenEvent)(
    PHANDLE            EventHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
    );
typedef ULONG(WINAPI* PFN_RtlNtStatusToDosError)(
    NTSTATUS Status
    );

PFN_NtCreateEvent g_origNtCreateEvent = nullptr;
PFN_NtOpenEvent g_origNtOpenEvent = nullptr;
PFN_RtlNtStatusToDosError g_origRtlNtStatusToDosError = nullptr;

#ifndef STATUS_OBJECT_NAME_EXISTS
#define STATUS_OBJECT_NAME_EXISTS ((NTSTATUS)0xC0000035L)
#endif


bool InstallHooks() {
    std::cout << "[+] Hook-DLL: Installing hooks...\n";

    // MinHook init
    if (MH_Initialize() != MH_OK) {
        emit_etw_error("MinHook init failed");
        return false;
    }

    // un-recursion helper
    HMODULE hKernelBase = GetModuleHandleW(L"kernelbase.dll");
    if (hKernelBase) {
        FARPROC p = GetProcAddress(hKernelBase, "GetCurrentProcessId");
        MH_CreateHook(p, Hook_GetCurrentProcessId, (LPVOID*)&g_origGetCurrentProcessId);
    }

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        emit_etw_error("ntdll not loaded");
        return false;
    }

    // all functions to hook (order does matter depending on the phase of the moon, or my buggy programming)
    HookInfo funcs[] = {
        {"NtQueryInformationProcess", (void*)Hook_NtQueryInformationProcess, (void**)&g_origNtQueryInformationProcess},
        {"NtCreateFile", (void*)Hook_NtCreateFile, (void**)&g_origNtCreateFile},
        {"NtOpenFile", (void*)Hook_NtOpenFile, (void**)&g_origNtOpenFile},
        {"NtReadFile", (void*)Hook_NtReadFile, (void**)&g_origNtReadFile},
        {"NtOpenProcess", (void*)Hook_NtOpenProcess, (void**)&g_origNtOpenProcess},
        {"NtReadVirtualMemory", (void*)Hook_NtReadVirtualMemory, (void**)&g_origNtReadVirtualMemory},
        {"NtWriteVirtualMemory", (void*)Hook_NtWriteVirtualMemory, (void**)&g_origNtWriteVirtualMemory},
        {"NtSuspendProcess", (void*)Hook_NtSuspendProcess, (void**)&g_origNtSuspendProcess},
        {"NtResumeProcess", (void*)Hook_NtResumeProcess, (void**)&g_origNtResumeProcess},
        {"NtClose", (void*)Hook_NtClose, (void**)&g_origNtClose},
        {"NtTerminateProcess", (void*)Hook_NtTerminateProcess, (void**)&g_origNtTerminateProcess}
    };

    /* more functions to hook:
    - NtCreateProcess(Ex)
    - NtSetInformationProcess
    - NtCreateThreadEx
    - NtQueryObject
    - NtQuerySecurityObject / NtSetSecurityObject
    - NtDebugActiveProcess
    - NtGetContextThread / NtSetContextThread
    */

    for (auto& f : funcs) {
        std::string name = f.name;
        FARPROC target = GetProcAddress(hNtdll, name.c_str());
        if (!target) {
            emit_etw_error(name + " not found in ntdll");
            return false;
        }

        if (MH_CreateHook(target, f.hook, (LPVOID*)f.original) != MH_OK) {
            emit_etw_error("Failed to hook " + name);
            return false;
        }
        else {
            emit_etw_ok("Hooked " + name);
        }
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        emit_etw_error("Failed to enable hooks");
        return false;
	}

    emit_etw_ok("++ NTDLL-HOOKER STARTED ++");
    return true;
}

void RemoveHooks() {
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
}

static const char* HOOKED_PROCS = "C:\\Users\\Public\\Downloads\\hooked.txt"; // should match the path in EDRi (utils.cpp)
static const char* TEMP_FILE = "C:\\Users\\Public\\Downloads\\temp.txt";

// append PID to file
void append_pid_to_file() {
    std::ofstream ofs(HOOKED_PROCS, std::ios::app);
    ofs << PID << "\n";
}

// check if already hooked
bool is_already_hooked() {
    std::ifstream ifs(HOOKED_PROCS);
    DWORD val;
    while (ifs >> val) {
        if (val == PID) {
            return true;
        }
    }
    return false;
}

void remove_pid_from_file() {
    std::ifstream ifs(HOOKED_PROCS);
    std::ofstream ofs(TEMP_FILE);
    DWORD val;
    while (ifs >> val) {
        if (val != PID) {
            ofs << val << "\n";
        }
    }
    ifs.close();
    ofs.close();
    // replace original file
    if (std::remove(HOOKED_PROCS) != 0) {
        std::cerr << "[!] Hook-DLL: Failed update hooked procs file\n";
        return;
    }
    if(std::rename(TEMP_FILE, HOOKED_PROCS) != 0) {
        std::cerr << "[!] Hook-DLL: Failed to store hooked procs again\n";
	}
}

DWORD WINAPI cleanup(bool remove_pid) {
    if (g_requestedStop) {
        return 0; // already cleaning up, do not reenter
	}

    std::cout << "[+] Hook-DLL: Cleaning up and unloading...\n";
	emit_etw_ok("-- NTDLL-HOOKER STOPPED --");
    StopResolverPool();
    RemoveHooks();
    TraceLoggingUnregister(g_hProvider); // after hooks removed!
    if (remove_pid) {
        remove_pid_from_file();
    }
	return 0;
}

// init a watcher thread to unload the DLL on event signal, ignore errors here
void watcher_thread() { // or just use a stopRequest.txt
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        std::wcerr << L"[!] Hook-DLL: Failed to get ntdll Handle\n";
        return;
    }

    g_origNtCreateEvent = (PFN_NtCreateEvent)GetProcAddress(ntdll, "NtCreateEvent");
    g_origNtOpenEvent = (PFN_NtOpenEvent)GetProcAddress(ntdll, "NtOpenEvent");
    g_origRtlNtStatusToDosError = (PFN_RtlNtStatusToDosError)GetProcAddress(ntdll, "RtlNtStatusToDosError");
    if (g_origNtCreateEvent == nullptr || g_origRtlNtStatusToDosError == nullptr) {
        std::wcerr << L"[!] Hook-DLL: Failed to get NtOpenEvent or RtlNtStatusToDosError address\n";
        return;
    }

    PSECURITY_DESCRIPTOR pSD = NULL;
    ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:(A;;GA;;;WD)", SDDL_REVISION_1, &pSD, NULL); // World: GENERIC_ALL

    // build NT name
    wchar_t eventName[128];
    swprintf_s(eventName, _countof(eventName), L"\\BaseNamedObjects\\Hooks_Stop_%lu", (unsigned long)PID);

    UNICODE_STRING usName = { 0 };
    usName.Buffer = (PWSTR)eventName;
    usName.Length = (USHORT)(wcslen(eventName) * sizeof(wchar_t));
    usName.MaximumLength = usName.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES oa = { 0 };
    InitializeObjectAttributes(&oa, &usName, OBJ_CASE_INSENSITIVE, NULL, pSD);

    HANDLE hEvent = NULL;
    NTSTATUS status = g_origNtCreateEvent(&hEvent, EVENT_ALL_ACCESS, &oa, NotificationEvent, FALSE);

	if (status == STATUS_OBJECT_NAME_EXISTS) { // Event already exists --> meaning already loaded, unloaded and loaded again here
        if (g_origNtOpenEvent == nullptr) {
            std::wcerr << L"[!] Hook-DLL: NtOpenEvent not resolved but needed to open existing event\n";
            return;
		}
        NTSTATUS s2 = g_origNtOpenEvent(&hEvent, EVENT_ALL_ACCESS, &oa);
        if (!NT_SUCCESS(s2)) {
			std::wcerr << L"[!] Hook-DLL: Failed to open existing stop event watcher " << eventName << L": " << g_origRtlNtStatusToDosError(s2) << L"\n";
            return;
        }
		ResetEvent(hEvent); // ensure non-signaled (imagine how long this took to debug...)
        std::wcout << L"[+] Hook-DLL: Opened stop event watcher for unloading: " << eventName << L"\n";
    }
    else if (!NT_SUCCESS(status)) {
        std::wcerr << L"[!] Hook-DLL: Failed to create stop event watcher " << eventName << L": " << g_origRtlNtStatusToDosError(status) << L"\n";
        return;
    }
    else {
        std::wcout << L"[+] Hook-DLL: Created stop event watcher for unloading: " << eventName << L"\n";
    }

    CreateThread(NULL, 0, [](LPVOID param) -> DWORD {
        HANDLE evt = (HANDLE)param;
		WaitForSingleObject(evt, INFINITE); // do not try to wait for H_PROC (own process on process shutdown) here, will crash the process
        cleanup(true);
        return 0;
        }
    , hEvent, 0, NULL);
}

DWORD WINAPI t_InitHooks(LPVOID param) {
    std::cout << "[+] Hook-DLL: Executing init thread...\n";

    PID = GetCurrentProcessId();
	if (is_already_hooked()) { // must be BEFORE H_PROC is re-assigned in case of multiple injections
        std::cout << "[+] Hook-DLL: Process " << PID << " already hooked, 2MB memory wasted (when reflectively injected, I'm not cleaning that up)\n";
        return 0;
    }

	H_PROC = OpenProcess(PROCESS_ALL_ACCESS | SYNCHRONIZE, FALSE, PID); // all access to duplicate handles later, synchronize for wait in watcher_thread

    TraceLoggingRegister(g_hProvider);
	watcher_thread(); // start watcher thread to unload DLL again
    InitResolverPool(8); // logical cpus * 2

    if (InstallHooks()) {
        append_pid_to_file();
    }
    else {
		Sleep(1000); // wait a bit to ensure any ETW messages are sent
		std::cout << "[-] Hook-DLL: Hook installation failed, unloading...\n";
        cleanup(false); // no need to remove PID from file
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(hinst); // dont notify for DLL_THREAD_ATTACH or DLL_THREAD_DETACH
        HANDLE hTread = CreateThread(nullptr, 0, t_InitHooks, nullptr, 0, nullptr);
        if (!hTread) {
            std::cerr << "[!] Hook-DLL: Failed to create init thread\n";
            return FALSE;
        }
        std::cout << "[+] Hook-DLL: Created init thread\n";
        break;
    }
	case DLL_THREAD_ATTACH: // disabled by DisableThreadLibraryCalls
        break;
    case DLL_THREAD_DETACH: // disabled by DisableThreadLibraryCalls
        break;
    case DLL_PROCESS_DETACH: // is not called when the DLL was reflectively loaded
        break;
    }
    return TRUE;
}
