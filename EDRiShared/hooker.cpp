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

__declspec(noinline) void __stdcall UniversalDllLoadingShellcodeEnd() {
}

static void* ResolveFunction(void* ptr) {
    unsigned char* b = (unsigned char*)ptr;
    if (b[0] == 0xE9) {
        int rel = *(int*)(b + 1);
        return (void*)(b + 5 + rel);
    }
    if (b[0] == 0xFF && b[1] == 0x25) {
        int disp = *(int*)(b + 2);
        void** target = (void**)(b + 6 + disp);
        return *target;
    }
    return ptr;
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
    ALIGN BOOTSTRAP_STATE	State = BOOTSTRAP_STATE::Pending;
    ALIGN DWORD				Ret = 0;
    ALIGN DWORD				LastWin32Error = 0;
    ALIGN void*             pArg = nullptr;
    ALIGN f_Routine			pRoutine = nullptr;
    ALIGN UINT_PTR			Buffer = 0;
};

// Space reserved for SR_REMOTE_DATA (sizeof X void pointers, see above)
#define VOID_PTR_BUFFER 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
#define SR_REMOTE_DATA_BUFFER VOID_PTR_BUFFER VOID_PTR_BUFFER VOID_PTR_BUFFER VOID_PTR_BUFFER VOID_PTR_BUFFER VOID_PTR_BUFFER

#define ProcessHandleInformation 51 // Information class 0x33

typedef DWORD(WINAPI* pfnGetProcessId)(HANDLE);
typedef DWORD(WINAPI* pfnGetThreadId)(HANDLE);

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

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;


// get McFullAccess mit Hendle
HANDLE GetFullAccessThread(DWORD targetProcessId, bool debug) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return NULL;

	HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
	if (!hK32) return NULL;

    auto NtQueryInformationProcess = (long (WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG))
        GetProcAddress(hNtdll, "NtQueryInformationProcess");
    auto NtQuerySystemInformation = (long (WINAPI*)(ULONG, PVOID, ULONG, PULONG))
        GetProcAddress(hNtdll, "NtQuerySystemInformation");
    auto _GetThreadId = (DWORD(WINAPI*)(HANDLE))
        GetProcAddress(hK32, "GetThreadId");

    if (!NtQueryInformationProcess || !NtQuerySystemInformation || !_GetThreadId) return NULL;

    // 1. Get the System Process/Thread info buffer first to verify states
    ULONG sysInfoSize = 1024 * 1024;
    BYTE* sysInfoBuffer = new BYTE[sysInfoSize];
    if (NtQuerySystemInformation(5, sysInfoBuffer, sysInfoSize, &sysInfoSize) != 0) {
        delete[] sysInfoBuffer;
        return NULL;
    }

    // 2. Query our internal process handle table
    ULONG bufferSize = 0x4000;
    PVOID buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ULONG returnLength = 0;

    // 20 = ProcessHandleInformation
    NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 20, buffer, bufferSize, &returnLength);
    if (status == 0xC0000004) { // Length mismatch
        VirtualFree(buffer, 0, MEM_RELEASE);
        bufferSize = returnLength;
        buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        status = NtQueryInformationProcess(GetCurrentProcess(), 20, buffer, bufferSize, &returnLength);
    }

    HANDLE preferredHandle = NULL;

    if (status == 0) {
        auto* localHandles = reinterpret_cast<PPROCESS_HANDLE_SNAPSHOT_INFORMATION>(buffer);
		if (localHandles == nullptr || localHandles->NumberOfHandles == 0) {
			if (buffer) VirtualFree(buffer, 0, MEM_RELEASE);
			delete[] sysInfoBuffer;
			return NULL;
		}

        // 3. Loop through our local handles
        for (ULONG_PTR i = 0; i < localHandles->NumberOfHandles; i++) {
            PROCESS_HANDLE_TABLE_ENTRY_INFO entry = localHandles->Handles[i];
            HANDLE hCurrent = reinterpret_cast<HANDLE>(entry.HandleValue);

            DWORD targetTid = _GetThreadId(hCurrent);
            if (targetTid == 0 || entry.GrantedAccess != THREAD_ALL_ACCESS) continue;

            // 4. Cross-reference this specific Tid against our system info buffer
            BYTE* currentProc = sysInfoBuffer;
            bool isSafe = false;

            while (true) {
                auto* proc = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(currentProc);

                if (reinterpret_cast<uintptr_t>(proc->UniqueProcessId) == targetProcessId) {
                    auto* threads = reinterpret_cast<SYSTEM_THREAD_INFORMATION*>(
                        currentProc + sizeof(SYSTEM_PROCESS_INFORMATION)
                        );

                    for (ULONG j = 0; j < proc->NumberOfThreads; ++j) {
                        DWORD currentTid = static_cast<DWORD>(reinterpret_cast<uintptr_t>(threads[j].ClientId.UniqueThread));

                        if (currentTid == targetTid) {
                            // Validate the thread state is safe (Not Waiting + WrQueue)
                            if (!(threads[j].ThreadState == 5 && threads[j].WaitReason == 8)) {
                                isSafe = true;
                            }
                            break;
                        }
                    }
                }

                if (proc->NextEntryOffset == 0 || isSafe) break;
                currentProc += proc->NextEntryOffset;
            }

            // If it belongs to our target process and passed the state checks, we take it!
            if (isSafe) {
                if (debug) {
                    printf("[+] Hooker: Verified handle %p (TID %lu) is safe and valid.\n", hCurrent, targetTid);
                }
                preferredHandle = hCurrent;
                break;
            }
        }
    }

    if (buffer) VirtualFree(buffer, 0, MEM_RELEASE);
    delete[] sysInfoBuffer;

    return preferredHandle;
}

// my funny code
std::string get_proc_access_details(DWORD granted) {
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

void print_granted_access(HANDLE h, int pid) {
    PUBLIC_OBJECT_BASIC_INFORMATION obi = {};
    ULONG ret = 0;
    NTSTATUS st = NtQueryObject(h, ObjectBasicInformation, &obi, sizeof(obi), &ret);
    if (st < 0) {
        std::cerr << "[!] Hooker: NtQueryObject failed at pid " << pid << ": 0x" << std::hex << st << "\n";
    }
    else {
		std::string details = get_proc_access_details(obi.GrantedAccess);
        std::cout << "[+] Hooker: GrantedAccess to pid " << pid << ": 0x" << std::hex << obi.GrantedAccess << std::dec << " -> " << details << "\n";
    }
}

// Inject DLL into target process via CreateRemoteThread + LoadLibrary onto DLL path
bool loadlibrary_inject(HANDLE hProcess, const std::string& dllPath, bool debug)
{
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
DWORD64 rva_to_offset(DWORD64 rva, DWORD64 base_address)
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
DWORD64 get_reflective_loader_offset(DWORD64 base_address, LPCSTR ReflectiveLoader_name)
{
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base_address + ((PIMAGE_DOS_HEADER)base_address)->e_lfanew);
    IMAGE_DATA_DIRECTORY exports_data_directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exports_data_directory.VirtualAddress == 0) return 0;

    PIMAGE_EXPORT_DIRECTORY export_directory = (PIMAGE_EXPORT_DIRECTORY)(base_address + rva_to_offset(exports_data_directory.VirtualAddress, base_address));
    DWORD* functions = (DWORD*)(base_address + rva_to_offset(export_directory->AddressOfFunctions, base_address));
    DWORD* names = (DWORD*)(base_address + rva_to_offset(export_directory->AddressOfNames, base_address));
    WORD* ords = (WORD*)(base_address + rva_to_offset(export_directory->AddressOfNameOrdinals, base_address));

    for (DWORD i = 0; i < export_directory->NumberOfNames; ++i)
    {
        char* name = (char*)(base_address + rva_to_offset(names[i], base_address));
        if (_stricmp(name, ReflectiveLoader_name) == 0) // case-insensitive
        {
            DWORD func_rva = functions[ords[i]];
            return rva_to_offset(func_rva, base_address);
        }
    }
    return 0;
}

// https://github.com/Paxai/DLLium/blob/de79b82bbeb011778b03022b21c0a9d623f3d813/DLLium/injection.cpp#L357
void RelocateImage(PBYTE buffer, uintptr_t targetBase) {
    auto* pDosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer);
    auto* pNt = reinterpret_cast<IMAGE_NT_HEADERS*>(buffer + pDosHdr->e_lfanew);
    auto* pOpt = &pNt->OptionalHeader;

    uintptr_t delta = targetBase - (uintptr_t)pOpt->ImageBase;
    if (delta == 0) return;

    auto relocDir = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.Size == 0) return;

    auto* pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(buffer + relocDir.VirtualAddress);
    uintptr_t relocEnd = (uintptr_t)pReloc + relocDir.Size;

    while (pReloc && (uintptr_t)pReloc < relocEnd && pReloc->SizeOfBlock > sizeof(IMAGE_BASE_RELOCATION)) {
        UINT  count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* info = reinterpret_cast<WORD*>(pReloc + 1);

        for (UINT i = 0; i < count; ++i) {
            WORD type = info[i] >> 12;
            WORD offset = info[i] & 0xFFF;

            if (type == IMAGE_REL_BASED_DIR64) {
                uintptr_t* patch = reinterpret_cast<uintptr_t*>(buffer + pReloc->VirtualAddress + offset);
                *patch += delta;
            }
            else if (type == IMAGE_REL_BASED_HIGHLOW) {
                uint32_t* patch = reinterpret_cast<uint32_t*>(buffer + pReloc->VirtualAddress + offset);
                *patch += (uint32_t)delta;
            }
        }

        pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            reinterpret_cast<BYTE*>(pReloc) + pReloc->SizeOfBlock);
    }
}


bool handle_cleanup(HANDLE hProcess, std::vector<LPVOID> remoteAddrs, LPVOID localAddr) {
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

// write dll to remote proc and handle patching from external -> minimal remote shellcode to setup
// https://github.com/Paxai/DLLium/blob/de79b82bbeb011778b03022b21c0a9d623f3d813/DLLium/injection.cpp#L161
bool external_inject(HANDLE hProcess, const std::string& dllPath, bool debug, bool hijackThread) {

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
        return handle_cleanup(hProcess, {}, nullptr);
    }

    BYTE* pLocalImage = (BYTE*)VirtualAlloc(nullptr, pOpt->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pLocalImage) {
		printf("[!] Hooker: VirtualAlloc failed at local process: %lu\n", GetLastError());
        return handle_cleanup(hProcess, {pRemoteTargetBase}, nullptr);
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
    if (delta == 0) { printf("[!] Hooker: Invalid delta (0) between local DLL base and remote process base\n"); return false; }

    auto relocDir = rpOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.Size == 0) { printf("[*] Hooker: Empty relocation dir found\n"); } // return false?

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
        }

        pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pReloc) + pReloc->SizeOfBlock);
        if (debug)
			printf("[+] Hooker: Processed relocation block at %p\n", pReloc);
    }

	// write the image to the remote process, same address
    if (!WriteProcessMemory(hProcess, pRemoteTargetBase, pLocalImage, pOpt->SizeOfImage, nullptr)) {
		printf("[!] Hooker: WriteProcessMemory failed: %lu at remote process\n", GetLastError());
		return handle_cleanup(hProcess, { pRemoteTargetBase }, pLocalImage);
    }
    VirtualFree(pLocalImage, 0, MEM_RELEASE);
    pLocalImage = nullptr;
    if (debug)
		printf("[+] Hooker: Wrote DLL to remote process memory at %p\n", pRemoteTargetBase);

    HMODULE hK32Local = GetModuleHandleA("kernel32.dll");
    if (!hK32Local) {
		printf("[!] Hooker: GetModuleHandleA failed for kernel32.dll at local process: %lu\n", GetLastError());
		return handle_cleanup(hProcess, { pRemoteTargetBase }, pLocalImage);
    }

    // get address of setup functions
    auto pRtlAddFuncTableLocal = (f_RtlAddFunctionTable)GetProcAddress(hK32Local, "RtlAddFunctionTable");
    auto pLoadLibraryALocal = (f_LoadLibraryA)GetProcAddress(hK32Local, "LoadLibraryA");
    auto pGetProcAddressLocal = (f_GetProcAddress)GetProcAddress(hK32Local, "GetProcAddress");

    if (!pLoadLibraryALocal || !pGetProcAddressLocal) {
		printf("[!] Hooker: GetProcAddress failed for LoadLibraryA or GetProcAddress at local process: %lu\n", GetLastError());
        return handle_cleanup(hProcess, { pRemoteTargetBase }, pLocalImage);
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
        return handle_cleanup(hProcess, { pRemoteTargetBase }, pLocalImage);
    }
    WriteProcessMemory(hProcess, pRemoteDllLoadingData, &dllLoadingData, sizeof(ShellcodeData), nullptr);
    if (debug)
		printf("[+] Hooker: Wrote required dllLoadingData to remote process memory at %p\n", pRemoteDllLoadingData);

    // hope this gets assembled after each other
    void* pLocalDllLoadingShellcodeStart = ResolveFunction((void*)UniversalDllLoadingShellcode);
    void* pLocalDllLoadingShellcodeEnd = ResolveFunction((void*)UniversalDllLoadingShellcodeEnd);
    size_t dllLoadingShellcodeSize = (uintptr_t)pLocalDllLoadingShellcodeEnd - (uintptr_t)pLocalDllLoadingShellcodeStart;

    // sanity check on the shellcodeSize, just set to 4kB if non-sensical and hope
    if (dllLoadingShellcodeSize == 0 || dllLoadingShellcodeSize > 0x8000) {
        printf("[-] Hooker: Warning, dllLoadingShellcodeSize has strange size %llu\n", dllLoadingShellcodeSize);
        dllLoadingShellcodeSize = 0x1000;
    }

	HANDLE hThread = nullptr;

    // https://github.com/guidedhacking/GuidedHacking-Injector/blob/e3c6eab04943b10881a7039dc27ff964c79fcb64/GH%20Injector%20Library/Thread%20Hijacking.cpp#L10
    if (hijackThread) {
        if (debug)
			printf("[*] Hooker: Attempting thread hijacking in target process\n");

        // 1. Identify and target a specific thread ID in the target process
		HANDLE hThread = GetFullAccessThread(GetProcessId(hProcess), debug);
        if (!hThread) {
			printf("[!] Hooker: Cannot find a safe and full access thread in hProc %p\n", hProcess);
			return handle_cleanup(hProcess, { pRemoteTargetBase, pRemoteDllLoadingData }, pLocalImage);
        }
		if (debug)
			printf("[+] Hooker: Opened thread %p for hijacking\n", hThread);

        // 2. Suspend the target thread to safely modify its state
        if (SuspendThread(hThread) == (DWORD)-1) {
            CloseHandle(hThread);
			printf("[!] Hooker: SuspendThread failed for thread %p: %lu\n", hThread, GetLastError());
            return handle_cleanup(hProcess, { pRemoteTargetBase, pRemoteDllLoadingData }, pLocalImage);
        }
        if (debug)
            printf("[+] Hooker: Suspended thread %p\n", hThread);

        // 3. Capture the current register state (specifically RIP) of the thread
        CONTEXT OldContext{ 0 };
        OldContext.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(hThread, &OldContext)) {
            ResumeThread(hThread);
            CloseHandle(hThread);
			printf("[!] Hooker: GetThreadContext failed for thread %p: %lu\n", hThread, GetLastError());
            return handle_cleanup(hProcess, { pRemoteTargetBase, pRemoteDllLoadingData }, pLocalImage);
        }

        // 4. x64 remote Shellcode bootstrap stub
        BYTE BootstrapShellcode[] =
        {
            SR_REMOTE_DATA_BUFFER

            0x48, 0x83, 0xEC, 0x08,													// + 0x00			-> sub	rsp, 0x08				; prepare stack for ret
            0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,								// + 0x04 (+ 0x07)	-> mov	[rsp + 0x00], RipLo		; store old rip as return address
            0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00,							// + 0x0B (+ 0x0F)	-> mov	[rsp + 0x04], RipHi		; 

            0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,		// + 0x13			-> push	r(a/c/d)x / r (8 - 11)	; save volatile registers
            0x9C,																	// + 0x1E			-> pushfq						; save flags register

            0x53,																	// + 0x1F			-> push rbx						; push rbx on stack (non volatile)
            0x48, 0x8D, 0x1D, 0xA9, 0xFF, 0xFF, 0xFF,								// + 0x20			-> lea	rbx, [-0x30]			; load pData into rbx

            0xC6, 0x03, 0x01,														// + 0x27			-> mov	byte ptr [rbx], 1		; set BootstrapData::BOOTSTRAP_STATE to Executing

            0x55,																	// + 0x2A			-> push rbp						; store rbp
            0x48, 0x8B, 0xEC,														// + 0x2B			-> mov	rbp, rsp				; save rsp to rbp
            0x48, 0x83, 0xE4, 0xF0,													// + 0x2E			-> and	rsp, -0x10				; 16-bit align rsp

            0x48, 0x8B, 0x4B, 0x18,													// + 0x32			-> mov  rcx, [rbx + 0x18]		; move pArg into rcx
            0x48, 0x83, 0xEC, 0x20,													// + 0x36			-> sub	rsp, 0x20				; reserve stack
            0xFF, 0x53, 0x20, 														// + 0x3A			-> call qword ptr [rbx + 0x20]	; call pRoutine
            0x48, 0x83, 0xC4, 0x20, 												// + 0x3D			-> add	rsp, 0x20				; update stack
            0x48, 0x89, 0x43, 0x08,													// + 0x41			-> mov	[rbx + 0x08], rax		; store returned value

            0x48, 0x8B, 0xE5,														// + 0x45			-> mov	rsp, rbp				; restore rsp
            0x5D,																	// + 0x48			-> pop	rbp						; restore rbp

            0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,					// + 0x49			-> mov	rax, gs:[0x30]			; GetLastError
            0x8B, 0x40, 0x68,														// + 0x52			-> mov	eax, [rax + 0x68]
            0x89, 0x43, 0x10,														// + 0x55			-> mov	[rbx + 0x10], eax		; store in BootstrapData::LastWin32Error

            0xC6, 0x03, 0x02,														// + 0x58			-> mov	byte ptr [rbx], 2		; set BootstrapData::BOOTSTRAP_STATE to Finished

            0x5B,																	// + 0x5B			-> pop rbx						; restore rbx

            0x9D,																	// + 0x5C			-> popfq						; restore flags register
            0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58,		// + 0x5D			-> pop r(11-8) / r(d/c/a)x		; restore volatile registers

            0xC3																	// + 0x68			-> ret							; return to old rip and continue execution
        }; // SIZE = 0x69 (+ sizeof(SR_REMOTE_DATA))

        // 5. Patch the original thread execution pointer (RIP) into the shellcode return sequence (right after SR_REMOTE_DATA)
        auto OldRIP = OldContext.Rip;
        DWORD dwLoRIP = (DWORD)((OldRIP) & 0xFFFFFFFF);
        DWORD dwHiRIP = (DWORD)((OldRIP >> 0x20) & 0xFFFFFFFF);

        *reinterpret_cast<DWORD*>(BootstrapShellcode + 0x07 + sizeof(BootstrapData)) = dwLoRIP;
        *reinterpret_cast<DWORD*>(BootstrapShellcode + 0x0F + sizeof(BootstrapData)) = dwHiRIP;

        // 6. Allocate space and write the DLLium (DLL loading shellcode) to remote proc
        f_Routine pRemoteDllLoadingShellcode = (f_Routine)VirtualAllocEx(hProcess, nullptr, dllLoadingShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pRemoteDllLoadingShellcode) {
            printf("[!] Hooker: VirtualAllocEx failed for DllLoadingShellcode: %lu\n", GetLastError());
            return handle_cleanup(hProcess, { pRemoteTargetBase, pRemoteDllLoadingData }, pLocalImage);
        }

        if (!WriteProcessMemory(hProcess, pRemoteDllLoadingShellcode, pLocalDllLoadingShellcodeStart, dllLoadingShellcodeSize, nullptr)) {
            ResumeThread(hThread);
            CloseHandle(hThread);
            printf("[!] Hooker WriteProcessMemory failed for DllLoadingShellcode: %lu\n", GetLastError());
            return handle_cleanup(hProcess, { pRemoteTargetBase, pRemoteDllLoadingData, pRemoteDllLoadingShellcode }, pLocalImage);
        }
        if (debug)
            printf("[+] Hooker: Wrote DllLoadingShellcode to remote process memory at %p, size: %zu bytes\n", pRemoteDllLoadingShellcode, dllLoadingShellcodeSize);

        // 7. Allocate space for bootstrap shellcode and data structure into remote proc
        void* pRemoteBootstrapShellcode = VirtualAllocEx(hProcess, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pRemoteBootstrapShellcode) {
            ResumeThread(hThread);
            CloseHandle(hThread);
            printf("[!] Hooker: VirtualAllocEx failed for BootstrapShellcode: %lu\n", GetLastError());
            return handle_cleanup(hProcess, { pRemoteTargetBase, pRemoteDllLoadingData, pRemoteDllLoadingShellcode }, pLocalImage);
        }
        if (debug)
            printf("[+] Hooker: Allocated memory for BootstrapShellcode at %p in remote process\n", pRemoteBootstrapShellcode);

        // 8. Initialize arguments inside BootstrapShellcode to point to (future) remote shellcode
        auto* sr_data = reinterpret_cast<BootstrapData*>(BootstrapShellcode); // get the head (start) of the shellcode as SR_REMOTE_DATA struct
        sr_data->pRoutine = pRemoteDllLoadingShellcode;                        // the DLLium (dll loading) shellcode
        sr_data->pArg = pRemoteDllLoadingData;                                 // the required data by DLLium to load the dll

        // high-level: hijack thread, prepare and allocate all shellcodes, then call remote bootstrap shellcode -> bootstrap prologue -> dllLoadingShellcode(dllLoadingData) -> bootstrap epilogue

        // now write the finished BootstrapShellcode to the remote proc
        if (!WriteProcessMemory(hProcess, pRemoteBootstrapShellcode, BootstrapShellcode, sizeof(BootstrapShellcode), nullptr)) {
            ResumeThread(hThread);
            CloseHandle(hThread);
            printf("[!] Hooker: WriteProcessMemory failed for BootstrapShellcode: %lu\n", GetLastError());
            return handle_cleanup(hProcess, { pRemoteTargetBase, pRemoteDllLoadingData, pRemoteDllLoadingShellcode, pRemoteBootstrapShellcode }, pLocalImage);
        }
        if (debug)
            printf("[+] Hooker: Updated pointers in BootstrapShellcode and written it to remote process\n");

        // 9. Redirect the thread's instruction pointer to point to our newly allocated shellcode
        void* pRemoteStartOfBootstrapShellcodeFunc = reinterpret_cast<BYTE*>(pRemoteBootstrapShellcode) + sizeof(BootstrapData);
        OldContext.Rip = reinterpret_cast<ULONG_PTR>(pRemoteStartOfBootstrapShellcodeFunc);

        if (!SetThreadContext(hThread, &OldContext)) {
            ResumeThread(hThread);
            CloseHandle(hThread);
			printf("[!] Hooker: SetThreadContext failed for thread %p: %lu\n", hThread, GetLastError());
            return handle_cleanup(hProcess, { pRemoteTargetBase, pRemoteDllLoadingData, pRemoteDllLoadingShellcode, pRemoteBootstrapShellcode }, pLocalImage);
        }
        if (debug)
            printf("[+] Hooker: SetThreadContext to RemoteStartOfBootstrapShellcodeFunc at %p\n", pRemoteStartOfBootstrapShellcodeFunc);

        // 10. Resume the thread to execute the payload
        ResumeThread(hThread);

        // 11. Check the execution state with memread into local bootstrapVerify
        BootstrapData bootstrapVerify{ };
        bootstrapVerify.State = BOOTSTRAP_STATE::Pending;
        bootstrapVerify.Ret = ERROR_SUCCESS;
        bootstrapVerify.LastWin32Error = ERROR_SUCCESS;

        DWORD timer = GetTickCount64();
        DWORD timeout = 60'000; // ms
        DWORD sleepTime = 100; // ms

        while (GetTickCount64() - timer < timeout) {
            Sleep(sleepTime);
            if (!ReadProcessMemory(hProcess, pRemoteBootstrapShellcode, &bootstrapVerify, sizeof(bootstrapVerify), nullptr)) {
                // How dare you?!
                printf("[!] Hooker: Cannot read back memory of injected proc which should never happen but happened, just return\n");
                handle_cleanup(hProcess, { }, pLocalImage);
                return true;
            }
            if (bootstrapVerify.State == BOOTSTRAP_STATE::Finished) {
                break;
            }
            // else loop until timeout
        }

        // 12. Output and cleanup 
        switch (bootstrapVerify.State) {
        case BOOTSTRAP_STATE::Pending:
            printf("[-] Hooker: BootstrapShellcode still not called? NANI?!\n"); // cleanup
            handle_cleanup(hProcess, { pRemoteTargetBase, pRemoteDllLoadingData, pRemoteDllLoadingShellcode, pRemoteBootstrapShellcode }, pLocalImage);
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
            handle_cleanup(hProcess, { pRemoteTargetBase, pRemoteDllLoadingData, pRemoteDllLoadingShellcode, pRemoteBootstrapShellcode }, pLocalImage);
            return true;
        }
    }
    else {

        // alloc space for the DLLium (DLL loading shellcode) in remote proc
        LPVOID pRemoteDllLoadingShellcode = VirtualAllocEx(hProcess, nullptr, dllLoadingShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pRemoteDllLoadingShellcode) {
            printf("[!] Hooker: VirtualAllocEx failed for remote dll loading shellcode: %lu\n", GetLastError());
            return handle_cleanup(hProcess, { pRemoteTargetBase, pRemoteDllLoadingData }, nullptr);
        }

        // write the DLLium (DLL loading shellcode) to remote proc
        if (!WriteProcessMemory(hProcess, pRemoteDllLoadingShellcode, pLocalDllLoadingShellcodeStart, dllLoadingShellcodeSize, nullptr)) {
            printf("[!] Hooker WriteProcessMemory failed for remote dll loading shellcode: %lu\n", GetLastError());
            return handle_cleanup(hProcess, { pRemoteTargetBase, pRemoteDllLoadingData, pRemoteDllLoadingShellcode }, nullptr);
        }
        if (debug)
            printf("[+] Hooker: Wrote dll loading shellcode to remote process memory at %p, size: %zu bytes\n", pRemoteDllLoadingShellcode, dllLoadingShellcodeSize);
        
        // and run it
        hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pRemoteDllLoadingShellcode, pRemoteDllLoadingData, 0, nullptr);
        if (!hThread) {
            printf("[!] Hooker: CreateRemoteThread failed: %lu\n", GetLastError());
            return handle_cleanup(hProcess, { pRemoteTargetBase, pRemoteDllLoadingData, pRemoteDllLoadingShellcode }, nullptr);
        }
    }

    printf("[+] Hooker: Remote thread created\n");

    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }
    CloseHandle(hProcess);

    if (debug)
        printf("[+] Hooker: DllMain successfully exited\n");
    return true;
}

// write dll to remote proc and call self-reflective loader (handles image address, system function resol., mem alloc, header copy, section copy, IAT resolution, relocations, and call DllMain)
bool reflective_inject(HANDLE hProcess, const std::string& dllPath, bool debug) {
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
    DWORD64 reflective_loader_offset = get_reflective_loader_offset((DWORD64)file_buf, "ReflectiveLoader");
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
bool inject_dll(int pid, const std::string& dllPath, bool debug, Action a, HANDLE hProcess, bool hijackThread) {
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
    print_granted_access(hProcess, pid);

	switch (a) {
	case LOADLIBRARY_INJECTION:
		if (debug) {
			std::cout << "[*] Hooker: Using LoadLibrary injection\n";
		}
		return loadlibrary_inject(hProcess, dllPath, debug);
	case EXTERNAL_INJECTION:
		if (debug) {
			std::cout << "[*] Hooker: Using External injection\n";
		}
		return external_inject(hProcess, dllPath, debug, hijackThread);
	case REFLECTIVE_INJECTION:
		if (debug) {
			std::cout << "[*] Hooker: Using Reflective injection\n";
		}
		return reflective_inject(hProcess, dllPath, debug);
	default:
		std::cerr << "[!] Hooker: Unknown action\n";
		CloseHandle(hProcess);
		return false;
	}
}
