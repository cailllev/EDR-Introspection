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
#include <atomic>

#include <MinHook.h>
#include <TraceLoggingProvider.h>

#pragma intrinsic(_ReturnAddress)

/*
* Things NOT to do when injecting reflectively (can crash the loader in t_InitHooks):
* 
* - global std::vectors modified in hooked functions
* - large __try __except blocks (code inside these blocks can easily crash the loader)
* - convoluted code flow (i.e. many declarations, if statements, ...)
* - removing the REFL INJ code below
* - too many strings in A SINGLE SWITCH STATEMENT ??
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
static UINT64 PID;

TRACELOGGING_DEFINE_PROVIDER(
    g_hProvider,
    "Hook-Provider", // name in the ETW, cannot be a variable
    (0x72248411, 0x7166, 0x4feb, 0xa3, 0x86, 0x34, 0xd8, 0xf3, 0x5b, 0xb6, 0x37)  // this cannot be a variable
);

// NtQueryInformationProcess definition (only in ntdll.dll defined)
typedef NTSTATUS(NTAPI* PFN_NtQueryInformationProcess)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength);

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

// own resolved ntdll funcs
static PFN_NtQueryInformationProcess pNtQueryInfoProcess = nullptr;

// trampolines created by MinHook
static PFN_NtCreateFile g_origNtCreateFile = nullptr;
static PFN_NtOpenFile g_origNtOpenFile = nullptr;
static PFN_NtReadFile g_origNtReadFile = nullptr;
static PFN_NtOpenProcess g_origNtOpenProcess = nullptr;
static PFN_NtReadVirtualMemory g_origNtReadVirtualMemory = nullptr;
static PFN_NtWriteVirtualMemory g_origNtWriteVirtualMemory = nullptr;
static PFN_NtClose g_origNtClose = nullptr;
static PFN_NtTerminateProcess g_origNtTerminateProcess = nullptr;

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
        "EDRHookTask", // the first event name is used for all events, unless using a manifest file
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
        "EDRHookError",
        TraceLoggingString(error.c_str(), "message"),
        TraceLoggingUInt64(ns, "ns_since_epoch"),
        TraceLoggingUInt64(PID, "targetpid")
    );
    std::cerr << "[!] Hook-DLL: " << error << "\n";
};

void emit_etw_msg_ns(const char msg[], UINT64 tpid, UINT64 ns) {
    TraceLoggingWrite(
        g_hProvider,
        "EDRHookTask",
        TraceLoggingString(msg, "message"),
        TraceLoggingUInt64(ns, "ns_since_epoch"),
        TraceLoggingUInt64(tpid, "targetpid")
    );
};

const size_t MSG_LEN = 128;
const size_t BIG_MSG_LEN = 1024;

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

// resolver pool
std::queue<ResolverTask> g_taskQueue;
std::mutex g_queueMutex;
std::condition_variable g_cv;
std::vector<std::thread> g_workers;
int MAX_QUEUE_SIZE = 65536; // arbitrary

void ResolverWorker() {
    while (true) {
        ResolverTask task = {};
        {
            std::unique_lock<std::mutex> lock(g_queueMutex);
            g_cv.wait(lock, [] { return !g_taskQueue.empty(); });

            if (g_taskQueue.empty())
                return;

            task = g_taskQueue.front();
            g_taskQueue.pop();
        }
        if (task.func && task.arg) { // invoke actual resolver
            task.func(task.arg);
        }
    }
}

void InitResolverPool(int numThreads) {
    for (int i = 0; i < numThreads; i++) {
        g_workers.emplace_back(ResolverWorker);
    }
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

// worker thread: resolve filename and emit ETW
DWORD WINAPI ReadFileResolverThread(LPVOID lpParam)
{
    FNF_ARGS* args = (FNF_ARGS*)lpParam;
    if (!args) return 0;
    HANDLE hFile = args->FileHandle;
    UINT64 ns = args->Timestamp;

    char msg[BIG_MSG_LEN];
    
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

    if (pNtQueryInfoProcess == nullptr || g_origNtReadVirtualMemory == nullptr) {
        free(args);
        return 0;
    }

    DWORD tpid = args->tpid;
    HANDLE hProcess = args->hProcess;
    uintptr_t offset = args->Offset;
    SIZE_T bytesToRead = args->NumberOfBytesToRead;
    UINT64 ns = args->Timestamp;

    char msg[BIG_MSG_LEN] = { 0 };
    char error[MSG_LEN] = { 0 };
    char vqeError[MSG_LEN] = { 0 };
    char combinedError[MSG_LEN] = { 0 };
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
            if (!err && pNtQueryInfoProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength) != 0) {
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

    char msg[BIG_MSG_LEN] = { 0 };
    char acc[MSG_LEN] = { 0 };
    char dispo[MSG_LEN] = { 0 };

    const ACCESS_MASK EDR_FILE_READ_DATA_SYNC = 0x100001;
    const ACCESS_MASK EDR_FILE_READ_ATTR_SYNC = 0x100080;
    const ACCESS_MASK EDR_FILE_READ_CONTROL = 0x20000;

    switch (DesiredAccess) {
    case FILE_GENERIC_READ: _snprintf_s(acc, sizeof(acc), _TRUNCATE, "0x%X:file_generic_read", (unsigned)DesiredAccess); break;
    case FILE_ALL_ACCESS: _snprintf_s(acc, sizeof(acc), _TRUNCATE, "0x%X:file_all_access", (unsigned)DesiredAccess); break;
    case FILE_READ_EA: _snprintf_s(acc, sizeof(acc), _TRUNCATE, "0x%X:file_read_ea", (unsigned)DesiredAccess); break;
    case EDR_FILE_READ_DATA_SYNC: _snprintf_s(acc, sizeof(acc), _TRUNCATE, "0x%X:file_read_data+sync", (unsigned)DesiredAccess); break;
    case EDR_FILE_READ_ATTR_SYNC: _snprintf_s(acc, sizeof(acc), _TRUNCATE, "0x%X:file_read_attr+sync", (unsigned)DesiredAccess); break;
    case EDR_FILE_READ_CONTROL: _snprintf_s(acc, sizeof(acc), _TRUNCATE, "0x%X:file_read_control", (unsigned)DesiredAccess); break;
    default: _snprintf_s(acc, sizeof(acc), _TRUNCATE, "0x%X:non-standard", (unsigned)DesiredAccess); break;
    }

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
            _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtCreateFile %s with DesiredAccess=%s and Disposition='%s'", nameBuf, acc, dispo);

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
            _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtCreateFile (no or invalid name) with DesiredAccess=%s and Disposition='%s'", acc, dispo);
        }
    }
    else {
        _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtCreateFile (no objectattrs) with DesiredAccess=%s and Disposition='%s'", acc, dispo);
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

    char msg[BIG_MSG_LEN];
    char acc[MSG_LEN] = { 0 };

    const ACCESS_MASK EDR_FILE_READ_DATA_SYNC = 0x100001;
    const ACCESS_MASK EDR_FILE_READ_ATTR_SYNC = 0x100080;
    const ACCESS_MASK EDR_FILE_READ_CONTROL = 0x20000;

    switch (DesiredAccess) {
    case FILE_GENERIC_READ: _snprintf_s(acc, sizeof(acc), _TRUNCATE, "0x%X:file_generic_read", (unsigned)DesiredAccess); break;
    case FILE_ALL_ACCESS: _snprintf_s(acc, sizeof(acc), _TRUNCATE, "0x%X:file_all_access", (unsigned)DesiredAccess); break;
    case FILE_READ_EA: _snprintf_s(acc, sizeof(acc), _TRUNCATE, "0x%X:file_read_ea", (unsigned)DesiredAccess); break;
    case EDR_FILE_READ_DATA_SYNC: _snprintf_s(acc, sizeof(acc), _TRUNCATE, "0x%X:file_read_data+sync", (unsigned)DesiredAccess); break;
    case EDR_FILE_READ_ATTR_SYNC: _snprintf_s(acc, sizeof(acc), _TRUNCATE, "0x%X:file_read_attr+sync", (unsigned)DesiredAccess); break;
    case EDR_FILE_READ_CONTROL: _snprintf_s(acc, sizeof(acc), _TRUNCATE, "0x%X:file_read_control", (unsigned)DesiredAccess); break;
    default: _snprintf_s(acc, sizeof(acc), _TRUNCATE, "0x%X:non-standard", (unsigned)DesiredAccess); break;
    }

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
                _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtOpenFile %s with DesiredAccess=%s", nameBuf, acc);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtOpenFile (invalid ObjectName pointer) with DesiredAccess=%s", acc);
            }
        }
        else {
            _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtOpenFile (no or invalid name) with DesiredAccess=%s", acc);
        }
    }
    else {
        _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtOpenFile (no objectattrs) with DesiredAccess=%s", acc);
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

    // duplicate handle to ensure validity in worker thread
    HANDLE dup = NULL;
    BOOL ok = false;
    if (FileHandle && FileHandle != INVALID_HANDLE_VALUE) {
        ok = DuplicateHandle(
            GetCurrentProcess(), FileHandle,
            GetCurrentProcess(), &dup,
            0, FALSE, DUPLICATE_SAME_ACCESS
        );
    }
    if (!ok) {
        if (dup) g_origNtClose(dup);
        char msg[MSG_LEN];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtReadFile handle=0x%p (error %lu duplicating handle)", (void*)dup, GetLastError());
        emit_etw_msg_ns(msg, PID, ns);
        return g_origNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    }

    // prepare args: dup may be NULL on failure; worker will handle it
    FNF_ARGS* args = (FNF_ARGS*)malloc(sizeof(FNF_ARGS));
    if (args) {
        args->FileHandle = dup;
        args->Timestamp = ns;
        if (!EnqueueResolverTask(ReadFileResolverThread, args)) {
            char msg[MSG_LEN];
            _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtReadFile handle=0x%p (resolver queue limit reached)", (void*)dup);
            emit_etw_msg_ns(msg, PID, ns);
            free(args);
        }
    }
    else { // allocation failed: cleanup duplicate
        if (dup) g_origNtClose(dup);
    }
    return g_origNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
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

    char msg[MSG_LEN];
    _snprintf_s(msg, sizeof(msg), _TRUNCATE, "NtOpenProcess with 0x%X", static_cast<unsigned int>(DesiredAccess));

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
    DWORD tpid = GetProcessId(ProcessHandle);
    uintptr_t addr = reinterpret_cast<uintptr_t>(BaseAddress);

    // duplicate handle to ensure validity in worker thread
    HANDLE dup = NULL;
    BOOL ok = false;
    if (ProcessHandle != NULL) { // do not check for INVALID_HANDLE_VALUE: https://devblogs.microsoft.com/oldnewthing/20230914-00/?p=108766
        ok = DuplicateHandle(
            GetCurrentProcess(), ProcessHandle,
            GetCurrentProcess(), &dup,
            0, FALSE, DUPLICATE_SAME_ACCESS
        );
    }
    if (!ok) { // this is the only check needed if a handle is valid to use later
        if (dup) g_origNtClose(dup);
        char msg[BIG_MSG_LEN];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
            "NtReadVirtualMemory 0x%llx bytes from Unknown!0x%0*llx, DuplicateHandle: error %lu duplicating handle",
            static_cast<unsigned long long>(NumberOfBytesToRead),
            static_cast<int>(sizeof(uintptr_t) * 2),
            static_cast<unsigned long long>(addr),
            GetLastError());
        emit_etw_msg_ns(msg, tpid, ns);
        return g_origNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
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
            char msg[BIG_MSG_LEN];
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
    return g_origNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
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
    DWORD tpid = GetProcessId(ProcessHandle);
    uintptr_t addr = reinterpret_cast<uintptr_t>(BaseAddress);

    char msg[MSG_LEN];
    _snprintf_s(msg, sizeof(msg), _TRUNCATE,
        "NtWriteVirtualMemory 0x%llx bytes at 0x%0*llx",
        static_cast<unsigned long long>(NumberOfBytesToWrite),
        static_cast<int>(sizeof(uintptr_t) * 2),
        static_cast<unsigned long long>(addr));

    emit_etw_msg_ns(msg, tpid, ns);
    return g_origNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

NTSTATUS NTAPI Hook_NtClose(
    HANDLE Handle
) {
    UINT64 ns = get_ns_time();
    DWORD tpid = GetProcessId(Handle);
    if (tpid != 0) { // ignore closing events of non proc handles
        emit_etw_msg_ns("NtClose process", tpid, ns);
    }
    return g_origNtClose(Handle);
}

NTSTATUS NTAPI Hook_NtTerminateProcess(
    HANDLE   Handle, 
    NTSTATUS ExitStatus
) {
    UINT64 ns = get_ns_time();
    DWORD tpid = GetProcessId(Handle);
    if (tpid != 0) { // ignore closing events of non proc handles 
        char msg[MSG_LEN];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
            "NtTerminateProcess with status 0x%lx",
            static_cast<LONG>(ExitStatus));
        emit_etw_msg_ns(msg, tpid, ns);
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

    // helper functions to resolve in ntdll.dll
    pNtQueryInfoProcess = (PFN_NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (pNtQueryInfoProcess == nullptr) return;

    // all functions to hook
    std::map<std::string, std::pair<void*, void**>> funcs = {
        {"NtCreateFile", {(void*)Hook_NtCreateFile, (void**)&g_origNtCreateFile}},
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
    PID = GetCurrentProcessId(); 
    InitResolverPool(8); // logical cpus * 2
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
    case DLL_PROCESS_DETACH:
        //RemoveHooks();
        //TraceLoggingUnregister(g_hProvider);
        break;
    }
    return TRUE;
}