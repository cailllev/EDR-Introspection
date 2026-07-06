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


__declspec(noinline) void __stdcall UniversalShellcode(ShellcodeData* pData) {
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

__declspec(noinline) void __stdcall UniversalShellcodeEnd() {
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

struct SR_REMOTE_DATA {
    unsigned char State;
    unsigned long long Ret;
    unsigned int LastWin32Error;
    void* pArg;
    void* pRoutine;
};

// Single direct function to locate a thread skipping WrQueue states
DWORD FindSafeThread(DWORD targetProcessId) {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (!ntdll) return 0;

    auto NtQuerySystemInformation = (long (WINAPI*)(ULONG, PVOID, ULONG, PULONG))GetProcAddress(ntdll, "NtQuerySystemInformation");

    ULONG size = 1024 * 1024;
    BYTE* buffer = new BYTE[size];

    // 5 = SystemProcessInformation
    if (!NtQuerySystemInformation || NtQuerySystemInformation(5, buffer, size, &size) != 0) {
        delete[] buffer;
        return 0;
    }

    DWORD chosenThreadId = 0;
    BYTE* current = buffer;

    while (true) {
        // Use the official SDK structure pointer
        auto* proc = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(current);

        // Explicitly check if this entry matches our target PID
        if (reinterpret_cast<uintptr_t>(proc->UniqueProcessId) == targetProcessId) {

            // Threads are positioned exactly after the process header structure
            auto* threads = reinterpret_cast<SYSTEM_THREAD_INFORMATION*>(
                current + sizeof(SYSTEM_PROCESS_INFORMATION)
                );

            for (ULONG i = 0; i < proc->NumberOfThreads; ++i) {
                DWORD tid = static_cast<DWORD>(reinterpret_cast<uintptr_t>(threads[i].ClientId.UniqueThread));

                // Skip the injector's own threads (should never happen, targetProcessId != Process Id)
                if (tid == GetCurrentThreadId()) continue;

                // 5 = Waiting, 8 = WrQueue (Thread Pool worker)
                if (threads[i].ThreadState == 5 && threads[i].WaitReason == 8) {
                    continue;
                }

                chosenThreadId = tid;
                break;
            }
        }

        // Jump explicitly to the next process block using the kernel-provided offset
        if (proc->NextEntryOffset == 0 || chosenThreadId != 0) break;
        current += proc->NextEntryOffset;
    }

    delete[] buffer;
    return chosenThreadId;
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

// write dll to remote proc and handle patching from external -> remote shellcode to setup
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

    std::vector<BYTE> pSrcData((size_t)fileSize);
    File.seekg(0, std::ios::beg);
    File.read((char*)pSrcData.data(), fileSize);
    File.close();
    if (debug)
        printf("[+] Hooker: DLL read into memory\n");

    auto* pDosLocal = reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData.data());
    if (pDosLocal->e_magic != IMAGE_DOS_SIGNATURE) { printf("[!] Unable to find magic bytes in DLL '%s'\n", dllPath.c_str()); return false; }

    auto* pNtLocal = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData.data() + pDosLocal->e_lfanew);
    if (pNtLocal->Signature != IMAGE_NT_SIGNATURE) { printf("[!] Unable to find NT header signature in DLL '%s'\n", dllPath.c_str()); return false; }
    auto* pOpt = &pNtLocal->OptionalHeader;

    LPVOID pTargetBase = VirtualAllocEx(hProcess, nullptr, pOpt->SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pTargetBase) {
		printf("[!] Hooker: VirtualAllocEx failed at remote process: %lu\n", GetLastError());
        return handle_cleanup(hProcess, {}, nullptr);
    }

    BYTE* pLocalImage = (BYTE*)VirtualAlloc(nullptr, pOpt->SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pLocalImage) {
		printf("[!] Hooker: VirtualAlloc failed at local process: %lu\n", GetLastError());
        return handle_cleanup(hProcess, {pTargetBase}, nullptr);
    }
    if (debug)
		printf("[+] Hooker: Allocated DLL into local %p and remote memory %p\n", pLocalImage, pTargetBase);

    memcpy(pLocalImage, pSrcData.data(), pOpt->SizeOfHeaders);

    auto* pSection = IMAGE_FIRST_SECTION(pNtLocal);
    for (UINT i = 0; i < pNtLocal->FileHeader.NumberOfSections; ++i, ++pSection) {
        if (pSection->SizeOfRawData > 0) {
            memcpy(pLocalImage + pSection->VirtualAddress,
                pSrcData.data() + pSection->PointerToRawData,
                pSection->SizeOfRawData);
            if (debug)
				printf("[+] Hooker: Copied section %.8s to local image\n", pSection->Name);
        }
    }

    // get local offsets for relocation 
    auto* pDosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(pLocalImage);
    auto* rpNt = reinterpret_cast<IMAGE_NT_HEADERS*>(pLocalImage + pDosHdr->e_lfanew);
    auto* rpOpt = &rpNt->OptionalHeader;

    uintptr_t delta = (uintptr_t)pTargetBase - (uintptr_t)rpOpt->ImageBase;
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
    if (!WriteProcessMemory(hProcess, pTargetBase, pLocalImage, pOpt->SizeOfImage, nullptr)) {
		printf("[!] Hooker: WriteProcessMemory failed: %lu at remote process\n", GetLastError());
		return handle_cleanup(hProcess, { pTargetBase }, pLocalImage);
    }
    VirtualFree(pLocalImage, 0, MEM_RELEASE);
    pLocalImage = nullptr;
    if (debug)
		printf("[+] Hooker: Wrote DLL to remote process memory at %p\n", pTargetBase);

    HMODULE hK32Local = GetModuleHandleA("kernel32.dll");
    if (!hK32Local) {
		printf("[!] Hooker: GetModuleHandleA failed for kernel32.dll at local process: %lu\n", GetLastError());
		return handle_cleanup(hProcess, { pTargetBase }, nullptr);
    }

    // get address of setup functions
    auto pRtlAddFuncTableLocal = (f_RtlAddFunctionTable)GetProcAddress(hK32Local, "RtlAddFunctionTable");
    auto pLoadLibraryALocal = (f_LoadLibraryA)GetProcAddress(hK32Local, "LoadLibraryA");
    auto pGetProcAddressLocal = (f_GetProcAddress)GetProcAddress(hK32Local, "GetProcAddress");

    if (!pLoadLibraryALocal || !pGetProcAddressLocal) {
		printf("[!] Hooker: GetProcAddress failed for LoadLibraryA or GetProcAddress at local process: %lu\n", GetLastError());
        return handle_cleanup(hProcess, { pTargetBase }, nullptr);
    }
    if (debug)
		printf("[+] Hooker: Resolved LoadLibraryA, GetProcAddress, and RtlAddFunctionTable at local process\n");

    ShellcodeData data = {};
    data.pDllBase = (uintptr_t)pTargetBase;
    data.EntryPoint = pOpt->AddressOfEntryPoint;
    data.ImportDir = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    data.RelocDir = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    data.ExceptionDir = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    data.ExceptionSize = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    data.TLSDir = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    data.pLoadLibraryA = pLoadLibraryALocal;
    data.pGetProcAddress = pGetProcAddressLocal;
    data.pRtlAddFunctionTable = pRtlAddFuncTableLocal;

	// allocate memory for shellcode data in remote process
    LPVOID pRemoteData = VirtualAllocEx(hProcess, nullptr, sizeof(ShellcodeData),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteData) {
		printf("[!] Hooker: VirtualAllocEx failed for remote data: %lu\n", GetLastError());
        return handle_cleanup(hProcess, { pTargetBase }, nullptr);
    }
    WriteProcessMemory(hProcess, pRemoteData, &data, sizeof(ShellcodeData), nullptr);
    if (debug)
		printf("[+] Hooker: Wrote shellcode data to remote process memory at %p\n", pRemoteData);

    void* scStart = ResolveFunction((void*)UniversalShellcode);
    void* scEnd = ResolveFunction((void*)UniversalShellcodeEnd);
    size_t shellcodeSize = (uintptr_t)scEnd - (uintptr_t)scStart;

	HANDLE hThread = nullptr;

    // https://github.com/guidedhacking/GuidedHacking-Injector/blob/e3c6eab04943b10881a7039dc27ff964c79fcb64/GH%20Injector%20Library/Thread%20Hijacking.cpp#L10
    if (hijackThread) {
        if (debug)
			printf("[*] Hooker: Attempting thread hijacking in target process\n");

        /*
        Technical Adjustments Needed:

        Allocate and Write the Main Payload Space:
        Before running the thread modification sequence, allocate memory in the target process specifically to hold the bootstrap execution code (scStart to scEnd) and write the bytes over. Let's call this pRemoteBootstrap.

        Update the Target Routine Address:
        Assign the remote destination pointer to your tracking structure rather than the local pointer:
        C++

        sr_data->pRoutine = pRemoteBootstrap;

        Pass the Correct Configuration Data:
        Your manual mapping details (pRemoteData containing the import directory, entry point, etc.) need to reach the bootstrap routine. In your current hijacking block, pArg is initialized as a null pointer:
        C++

        int* pArg = 0; 
        sr_data->pArg = pArg;

        To allow the bootstrap function to locate your manual-mapped DLL headers, update pArg to point to the remote configuration data block allocated earlier:
        C++

        sr_data->pArg = pRemoteData;
        */

        // 1. Identify and target a specific thread ID in the target process
        // (Target thread identification logic omitted for brevity)DWORD FindTargetThread(DWORD targetProcessId) {
        DWORD chosenThreadId = FindSafeThread(GetProcessId(hProcess));
		if (!chosenThreadId) {
			printf("[!] Hooker: No suitable thread found for hijacking\n");
			return handle_cleanup(hProcess, { pTargetBase, pRemoteData }, nullptr);
		}

        HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, chosenThreadId);
        if (!hThread) {
			printf("[!] Hooker: OpenThread failed for thread ID %lu: %lu\n", chosenThreadId, GetLastError());
			return handle_cleanup(hProcess, { pTargetBase, pRemoteData }, nullptr);
        }
		if (debug)
			printf("[+] Hooker: Opened thread ID %lu for hijacking\n", chosenThreadId);

        // 2. Suspend the target thread to safely modify its state
        if (SuspendThread(hThread) == (DWORD)-1) {
            CloseHandle(hThread);
			printf("[!] Hooker: SuspendThread failed for thread ID %lu: %lu\n", chosenThreadId, GetLastError());
            return handle_cleanup(hProcess, { pTargetBase, pRemoteData }, nullptr);
        }

        // 3. Capture the current register state (specifically RIP) of the thread
        CONTEXT OldContext{ 0 };
        OldContext.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(hThread, &OldContext)) {
            ResumeThread(hThread);
            CloseHandle(hThread);
			printf("[!] Hooker: GetThreadContext failed for thread ID %lu: %lu\n", chosenThreadId, GetLastError());
            return handle_cleanup(hProcess, { pTargetBase, pRemoteData }, nullptr);
        }

        // 4. Allocate memory in the target process for the shellcode and data structure
        void* pMem = VirtualAllocEx(hProcess, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pMem) {
            ResumeThread(hThread);
            CloseHandle(hThread);
			printf("[!] Hooker: VirtualAllocEx failed for shellcode: %lu\n", GetLastError());
            return handle_cleanup(hProcess, { pTargetBase, pRemoteData }, nullptr);
        }
        if (debug)
			printf("[+] Hooker: Suspended thread, copied context and allocated memory for shellcode at %p in target process\n", pMem);

        // 5. x64 Shellcode stub
        BYTE Shellcode[] =
        {
            // Space reserved at the beginning for SR_REMOTE_DATA
            0x48, 0x83, 0xEC, 0x08,                                 // sub rsp, 0x08            ; Prepare stack
            0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,               // mov [rsp], RipLo         ; Placeholder for original RIP (Low)
            0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00,         // mov [rsp+4], RipHi       ; Placeholder for original RIP (High)
            0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, // push registers ; Save volatile registers
            0x9C,                                                   // pushfq                   ; Save flags
            0x53,                                                   // push rbx                 ; Save non-volatile RBX
            0x48, 0x8D, 0x1D, 0xA9, 0xFF, 0xFF, 0xFF,               // lea rbx, [-0x30]         ; Point RBX to SR_REMOTE_DATA
            0xC6, 0x03, 0x01,                                       // mov byte ptr [rbx], 1    ; Set state to Executing
            0x55,                                                   // push rbp
            0x48, 0x8B, 0xEC,                                       // mov rbp, rsp
            0x48, 0x83, 0xE4, 0xF0,                                 // and rsp, -0x10           ; Align stack to 16 bytes for x64 calling convention
            0x48, 0x8B, 0x4B, 0x18,                                 // mov rcx, [rbx + 0x18]    ; Move pArg into RCX (1st argument)
            0x48, 0x83, 0xEC, 0x20,                                 // sub rsp, 0x20            ; Allocate shadow space
            0xFF, 0x53, 0x20,                                       // call qword ptr [rbx+0x20]; Invoke target routine
            0x48, 0x83, 0xC4, 0x20,                                 // add rsp, 0x20
            0x48, 0x89, 0x43, 0x08,                                 // mov [rbx + 0x08], rax    ; Save return value
            0x48, 0x8B, 0xE5,                                       // mov rsp, rbp
            0x5D,                                                   // pop rbp
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,   // mov rax, gs:[0x30]       ; Get TEB
            0x8B, 0x40, 0x68,                                       // mov eax, [rax + 0x68]    ; Get LastError
            0x89, 0x43, 0x10,                                       // mov [rbx + 0x10], eax    ; Save LastError
            0xC6, 0x03, 0x02,                                       // mov byte ptr [rbx], 2    ; Set state to Finished
            0x5B,                                                   // pop rbx
            0x9D,                                                   // popfq                    ; Restore flags
            0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, // pop registers  ; Restore registers
            0xC3                                                    // ret                      ; Return to original RIP
        };

        // 6. Patch the original thread execution pointer (RIP) into the shellcode return sequence
        auto OldRIP = OldContext.Rip;
        DWORD dwLoRIP = (DWORD)((OldRIP) & 0xFFFFFFFF);
        DWORD dwHiRIP = (DWORD)((OldRIP >> 0x20) & 0xFFFFFFFF);

        *reinterpret_cast<DWORD*>(Shellcode + 0x07 + sizeof(SR_REMOTE_DATA)) = dwLoRIP;
        *reinterpret_cast<DWORD*>(Shellcode + 0x0F + sizeof(SR_REMOTE_DATA)) = dwHiRIP;

        // 7. Initialize arguments inside the data block header of the shellcode
		int* pArg = 0; // Example argument to pass to the target routine
        auto* sr_data = reinterpret_cast<SR_REMOTE_DATA*>(Shellcode);
        sr_data->pArg = pArg;
        sr_data->pRoutine = scStart; // above shellcode from DLLium
        sr_data->State = 0; // Pending

        // 8. Write the shellcode into the remote process memory space
        if (!WriteProcessMemory(hProcess, pMem, Shellcode, sizeof(Shellcode), nullptr)) {
            ResumeThread(hThread);
            CloseHandle(hThread);
			printf("[!] Hooker: WriteProcessMemory failed for shellcode: %lu\n", GetLastError());
            return handle_cleanup(hProcess, { pTargetBase, pRemoteData, pMem }, nullptr);
        }

        // 9. Redirect the thread's instruction pointer to point to our newly allocated shellcode
        void* pRemoteFunc = reinterpret_cast<BYTE*>(pMem) + sizeof(SR_REMOTE_DATA);
        OldContext.Rip = reinterpret_cast<ULONG_PTR>(pRemoteFunc);

        if (!SetThreadContext(hThread, &OldContext)) {
            ResumeThread(hThread);
            CloseHandle(hThread);
			printf("[!] Hooker: SetThreadContext failed for thread ID %lu: %lu\n", chosenThreadId, GetLastError());
            return handle_cleanup(hProcess, { pTargetBase, pRemoteData, pMem }, nullptr);
        }

        // 10. Resume the thread to execute the payload
        ResumeThread(hThread);
    }
    else {
        if (shellcodeSize == 0 || shellcodeSize > 0x8000) {
            shellcodeSize = 0x1000;
        }

        LPVOID pRemoteShellcode = VirtualAllocEx(hProcess, nullptr, shellcodeSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pRemoteShellcode) {
            printf("[!] Hooker: VirtualAllocEx failed for remote shellcode: %lu\n", GetLastError());
            return handle_cleanup(hProcess, { pTargetBase, pRemoteData }, nullptr);
        }
        WriteProcessMemory(hProcess, pRemoteShellcode, scStart, shellcodeSize, nullptr);
        if (debug)
            printf("[+] Hooker: Wrote shellcode to remote process memory at %p, size: %zu bytes\n", pRemoteShellcode, shellcodeSize);
        
        hThread = CreateRemoteThread(hProcess, nullptr, 0,
            (LPTHREAD_START_ROUTINE)pRemoteShellcode, pRemoteData, 0, nullptr);
        if (!hThread) {
            printf("[!] Hooker: CreateRemoteThread failed: %lu\n", GetLastError());
            return handle_cleanup(hProcess, { pTargetBase, pRemoteData, pRemoteShellcode }, nullptr);
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
