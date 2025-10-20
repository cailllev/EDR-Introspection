#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <fstream>
#include <iostream>
#include <string>
#include <stdint.h>

static std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return {};
    auto sz = (size_t)f.tellg();
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(sz);
    if (!f.read((char*)buf.data(), sz)) return {};
    return buf;
}

static uintptr_t get_local_module_base(const char* name) {
    HMODULE h = GetModuleHandleA(name);
    return (uintptr_t)h;
}

std::string wchar2string(const wchar_t* wideString) {
    if (!wideString) {
        return "";
    }
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wideString, -1, nullptr, 0, nullptr, nullptr);
    if (sizeNeeded <= 0) {
        return "";
    }
    std::string ret(sizeNeeded - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wideString, -1, &ret[0], sizeNeeded, nullptr, nullptr);
    return ret;
}

// find module base in remote process using Toolhelp snapshot
static uintptr_t get_remote_module_base(DWORD pid, const char* modulename) {
    uintptr_t base = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32 me;
    me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do {
			std::string name = wchar2string(me.szModule);
            if (_stricmp(name.c_str(), modulename) == 0) {
                base = (uintptr_t)me.modBaseAddr;
                break;
            }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return base;
}

// helper: write data to remote and check
static bool write_remote(HANDLE hProc, LPVOID remote, const void* data, SIZE_T size) {
    SIZE_T wrote = 0;
    bool ret = WriteProcessMemory(hProc, remote, data, size, &wrote) && wrote == size;
    FlushInstructionCache(hProc, remote, size);
    return ret;
}

// use CreateRemoteThread to call LoadLibraryA in target to ensure a module is loaded
static uintptr_t remote_load_library(HANDLE hProc, DWORD pid, const char* dllName) {
    size_t nameLen = strlen(dllName) + 1;
    LPVOID remoteStr = VirtualAllocEx(hProc, NULL, nameLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteStr) return 0;
    if (!write_remote(hProc, remoteStr, dllName, nameLen)) {
        VirtualFreeEx(hProc, remoteStr, 0, MEM_RELEASE);
        return 0;
    }
    // get local LoadLibraryA address
    FARPROC ll = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!ll) { VirtualFreeEx(hProc, remoteStr, 0, MEM_RELEASE); return 0; }
    HANDLE hThr = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)ll, remoteStr, 0, NULL);
    if (!hThr) { VirtualFreeEx(hProc, remoteStr, 0, MEM_RELEASE); return 0; }
    WaitForSingleObject(hThr, INFINITE);
    CloseHandle(hThr);
    // cleanup remote string
    VirtualFreeEx(hProc, remoteStr, 0, MEM_RELEASE);
    // now try to look up module base via snapshot (may require a short delay; we do a quick retry)
    uintptr_t base = 0;
    for (int i = 0; i < 10 && !base; i++) {
        Sleep(10);
        base = get_remote_module_base(pid, dllName);
    }
    return base;
}

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cout << "Usage: " << argv[0] << " <path/to/dll> <pid>\n";
        return 1;
    }
    std::string dllPath = argv[1];
    DWORD pid = (DWORD)atoi(argv[2]);

    // read dll bytes
    auto dll = read_file(dllPath);
    if (dll.empty()) { std::cerr << "Failed to read DLL\n"; return 2; }

    // basic PE checks
    if (dll.size() < sizeof(IMAGE_DOS_HEADER)) { std::cerr << "Not a PE\n"; return 3; }
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dll.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { std::cerr << "Bad DOS sig\n"; return 4; }
    IMAGE_NT_HEADERS64* nth = (IMAGE_NT_HEADERS64*)(dll.data() + dos->e_lfanew);
    if (nth->Signature != IMAGE_NT_SIGNATURE) { std::cerr << "Bad NT sig\n"; return 5; }
    if (nth->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) { std::cerr << "Not x64 DLL (this injector is x64-only)\n"; return 6; }

    SIZE_T imageSize = nth->OptionalHeader.SizeOfImage;
    SIZE_T headersSize = nth->OptionalHeader.SizeOfHeaders;
    uint64_t preferredBase = nth->OptionalHeader.ImageBase;

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { std::cerr << "OpenProcess failed: " << GetLastError() << "\n"; return 7; }

    // allocate remote image memory (we choose any address; relocations will be applied)
    LPVOID remoteImage = VirtualAllocEx(hProc, NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteImage) { std::cerr << "VirtualAllocEx failed: " << GetLastError() << "\n"; CloseHandle(hProc); return 8; }

    // prepare a local working copy to apply relocations & fill IAT with *remote* addresses
    std::vector<uint8_t> localImage(imageSize);
    memset(localImage.data(), 0, imageSize);
    // copy headers
    memcpy(localImage.data(), dll.data(), headersSize);

    // copy sections
    IMAGE_SECTION_HEADER* sect = IMAGE_FIRST_SECTION(nth);
    for (unsigned i = 0; i < nth->FileHeader.NumberOfSections; ++i) {
        const IMAGE_SECTION_HEADER& s = sect[i];
        if (s.SizeOfRawData > 0 && s.PointerToRawData + s.SizeOfRawData <= dll.size()) {
            memcpy(localImage.data() + s.VirtualAddress, dll.data() + s.PointerToRawData, s.SizeOfRawData);
        }
        else {
            // zero virtual size
            if (s.Misc.VirtualSize) memset(localImage.data() + s.VirtualAddress, 0, s.Misc.VirtualSize);
        }
    }

    // 1) Relocations: apply relocations in localImage for target base = remoteImage
    intptr_t delta = (intptr_t)((uintptr_t)remoteImage - (intptr_t)preferredBase);
    if (delta != 0 && nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto relocDirRVA = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        auto reloc = (IMAGE_BASE_RELOCATION*)(localImage.data() + relocDirRVA);

        uint64_t iatVal = 0;
        ReadProcessMemory(hProc, (uint8_t*)remoteImage + relocDirRVA, &iatVal, sizeof(iatVal), nullptr);
        printf("IAT[0] = 0x%llX\n", iatVal);

        SIZE_T processed = 0;
        SIZE_T relocSize = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        while (processed < relocSize && reloc->SizeOfBlock) {
            DWORD entries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* list = (WORD*)((uint8_t*)reloc + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD i = 0; i < entries; ++i) {
                WORD e = list[i];
                WORD type = e >> 12;
                WORD offset = e & 0x0FFF;
                uint8_t* where = localImage.data() + reloc->VirtualAddress + offset;
                if (type == IMAGE_REL_BASED_DIR64) {
                    uint64_t* p = (uint64_t*)where;
                    *p = (uint64_t)((intptr_t)(*p) + delta);
                }
                else if (type == IMAGE_REL_BASED_HIGHLOW) {
                    uint32_t* p = (uint32_t*)where;
                    *p = (uint32_t)((intptr_t)(*p) + (uint32_t)delta);
                } // other types ignored
            }
            processed += reloc->SizeOfBlock;
            reloc = (IMAGE_BASE_RELOCATION*)((uint8_t*)reloc + reloc->SizeOfBlock);
        }
    }


    // 2) Resolve imports: for each imported DLL, ensure it is loaded in remote (or load it), then write remote function addresses into IAT
    auto importDir = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size) {
        auto importDesc = (IMAGE_IMPORT_DESCRIPTOR*)(localImage.data() + importDir.VirtualAddress);
        while (importDesc->Name) {
            char* dllName = (char*)(localImage.data() + importDesc->Name);

            // ensure remote has this module, otherwise load it remotely
            uintptr_t remoteModBase = get_remote_module_base(pid, dllName);
            if (remoteModBase == 0) {
                // attempt remote LoadLibraryA
                remoteModBase = remote_load_library(hProc, pid, dllName);
                if (remoteModBase == 0) {
                    std::cerr << "Failed to ensure remote module loaded: " << dllName << "\n";
                    VirtualFreeEx(hProc, remoteImage, 0, MEM_RELEASE);
                    CloseHandle(hProc);
                    return 9;
                }
				std::cout << "Loaded remote module " << dllName << " at " << std::hex << remoteModBase << std::dec << "\n";
            }

            // local handle for computing offset
            HMODULE localHM = LoadLibraryA(dllName); // should succeed (we are likely to have same system DLLs)
            if (!localHM) {
                std::cerr << "LoadLibraryA locally failed for " << dllName << "\n";
                VirtualFreeEx(hProc, remoteImage, 0, MEM_RELEASE);
                CloseHandle(hProc);
                return 10;
            }
            uintptr_t localBase = (uintptr_t)localHM;

            IMAGE_THUNK_DATA64* thunkILT = (IMAGE_THUNK_DATA64*)(localImage.data() + importDesc->OriginalFirstThunk);
            IMAGE_THUNK_DATA64* thunkIAT = (IMAGE_THUNK_DATA64*)(localImage.data() + importDesc->FirstThunk);
            if (!importDesc->OriginalFirstThunk) thunkILT = thunkIAT;
            while (thunkILT->u1.AddressOfData) {
                uintptr_t funcAddrRemote = 0;
                if (thunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    // import by ordinal
                    WORD ord = IMAGE_ORDINAL64(thunkILT->u1.Ordinal);
                    FARPROC localFunc = GetProcAddress(localHM, (LPCSTR)(uintptr_t)ord);
                    if (!localFunc) { std::cerr << "GetProcAddress local by ordinal failed\n"; VirtualFreeEx(hProc, remoteImage, 0, MEM_RELEASE); CloseHandle(hProc); return 11; }
                    uintptr_t localFuncAddr = (uintptr_t)localFunc;
                    uintptr_t offset = localFuncAddr - localBase;
                    funcAddrRemote = remoteModBase + offset;
                }
                else {
                    IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(localImage.data() + thunkILT->u1.AddressOfData);
                    const char* name = (const char*)ibn->Name;
                    FARPROC localFunc = GetProcAddress(localHM, name);
                    if (!localFunc) {
                        std::cerr << "GetProcAddress local failed for " << name << "\n";
                        VirtualFreeEx(hProc, remoteImage, 0, MEM_RELEASE);
                        CloseHandle(hProc);
                        return 12;
                    }
                    uintptr_t localFuncAddr = (uintptr_t)localFunc;
                    uintptr_t offset = localFuncAddr - localBase;
                    funcAddrRemote = remoteModBase + offset;
                }
                // write the remote function pointer into the IAT entry in localImage
                thunkIAT->u1.Function = (ULONGLONG)funcAddrRemote;

                ++thunkILT; ++thunkIAT;
            }
            ++importDesc;
        }
    }

    // 3) write the prepared localImage into remote memory
    if (!write_remote(hProc, remoteImage, localImage.data(), imageSize)) {
        std::cerr << "WriteProcessMemory image failed: " << GetLastError() << "\n";
        VirtualFreeEx(hProc, remoteImage, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 13;
    }

    // 4) set proper protections for sections in remote (iterate section headers and call VirtualProtectEx)
    for (unsigned i = 0; i < nth->FileHeader.NumberOfSections; ++i) {
        const IMAGE_SECTION_HEADER& s = sect[i];
        LPVOID secAddr = (LPVOID)((uintptr_t)remoteImage + s.VirtualAddress);
        SIZE_T secSize = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
        if (secSize == 0) continue;
        DWORD protect = PAGE_NOACCESS;
        bool isExec = (s.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        bool isRead = (s.Characteristics & IMAGE_SCN_MEM_READ) != 0;
        bool isWrite = (s.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        if (isExec) {
            if (isRead) protect = isWrite ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
            else protect = isWrite ? PAGE_EXECUTE_WRITECOPY : PAGE_EXECUTE;
        }
        else {
            if (isRead) protect = isWrite ? PAGE_READWRITE : PAGE_READONLY;
            else protect = isWrite ? PAGE_WRITECOPY : PAGE_NOACCESS;
        }
        DWORD old = 0;
        if (!VirtualProtectEx(hProc, secAddr, secSize, protect, &old)) {
            // not fatal; continue
        }
    }

    // 5) Build a small x64 trampoline that calls DllMain(remoteImage, DLL_PROCESS_ATTACH, NULL)
    // trampoline (assembly sequence):
    // mov rcx, <remoteImage>        ; rcx = hModule
    // mov rdx, 2                    ; rdx = DLL_PROCESS_ATTACH
    // xor r8, r8                    ; r8 = NULL
    // mov rax, <entry>              ; rax = entry
    // call rax
    // xor ecx, ecx                  ; set return 0
    // ret
    //
    // Machine bytes assembled at runtime (little-endian imm64)

    uint64_t remoteBaseAddr = (uint64_t)remoteImage;
    uint64_t entryRVA = (uint64_t)nth->OptionalHeader.AddressOfEntryPoint;
    uint64_t remoteEntry = remoteBaseAddr + entryRVA;

    std::vector<uint8_t> tramp;
    // mov rcx, imm64
    tramp.push_back(0x48); tramp.push_back(0xB9);
    for (int i = 0; i < 8; i++) tramp.push_back((uint8_t)((remoteBaseAddr >> (8 * i)) & 0xFF));
    // mov rdx, imm64 (2)
    tramp.push_back(0x48); tramp.push_back(0xBA);
    uint64_t dword2 = 2;
    for (int i = 0; i < 8; i++) tramp.push_back((uint8_t)((dword2 >> (8 * i)) & 0xFF));
    // xor r8, r8
    tramp.push_back(0x4D); tramp.push_back(0x31); tramp.push_back(0xC0);
    // mov rax, imm64 (entry)
    tramp.push_back(0x48); tramp.push_back(0xB8);
    for (int i = 0; i < 8; i++) tramp.push_back((uint8_t)((remoteEntry >> (8 * i)) & 0xFF));
    // call rax
    tramp.push_back(0xFF); tramp.push_back(0xD0);
    // xor eax,eax
    tramp.push_back(0x33); tramp.push_back(0xC0);
    // ret
    tramp.push_back(0xC3);

    // write trampoline to remote
    LPVOID remoteTramp = VirtualAllocEx(hProc, NULL, tramp.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteTramp) { std::cerr << "VirtualAllocEx tramp failed\n"; VirtualFreeEx(hProc, remoteImage, 0, MEM_RELEASE); CloseHandle(hProc); return 14; }
    if (!write_remote(hProc, remoteTramp, tramp.data(), tramp.size())) {
        std::cerr << "WriteProcessMemory tramp failed: " << GetLastError() << "\n";
        VirtualFreeEx(hProc, remoteTramp, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteImage, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 15;
    }

	std::cout << "Press Enter to execute remote DllMain...";
	std::cin.get();

    // execute remote trampoline
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)remoteTramp, NULL, 0, NULL);
    if (!hThread) { std::cerr << "CreateRemoteThread failed: " << GetLastError() << "\n"; VirtualFreeEx(hProc, remoteTramp, 0, MEM_RELEASE); VirtualFreeEx(hProc, remoteImage, 0, MEM_RELEASE); CloseHandle(hProc); return 16; }
    WaitForSingleObject(hThread, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    std::cout << "Remote DllMain returned: 0x" << std::hex << exitCode << "\n";

    // cleanup trampoline (optionally keep it)
    VirtualFreeEx(hProc, remoteTramp, 0, MEM_RELEASE);

    CloseHandle(hThread);
    CloseHandle(hProc);

    std::cout << "Done. Remote image at " << remoteImage << "\n";
    return 0;
}