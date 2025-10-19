#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>

static SIZE_T align_up(SIZE_T v, SIZE_T a) { return (v + a - 1) & ~(a - 1); }

std::vector<char> read_file_bytes(const char* path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return {};
    std::streamsize sz = f.tellg();
    f.seekg(0, std::ios::beg);
    std::vector<char> buf((size_t)sz);
    if (!f.read(buf.data(), sz)) return {};
    return buf;
}

HMODULE manual_map_from_memory(const uint8_t* src, size_t srcSize) {
    if (!src) return nullptr;

    auto dos = (IMAGE_DOS_HEADER*)src;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto nth = (IMAGE_NT_HEADERS*)(src + dos->e_lfanew);
    if (nth->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    IMAGE_OPTIONAL_HEADER& opt = nth->OptionalHeader;
    const SIZE_T imageSize = opt.SizeOfImage;
    const SIZE_T headersSize = opt.SizeOfHeaders;
    const DWORD align = opt.SectionAlignment;

    // Allocate memory for the image
    uint8_t* imageBase = (uint8_t*)VirtualAlloc(nullptr, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!imageBase) return nullptr;

    // Copy headers
    memcpy(imageBase, src, headersSize);

    // Copy sections
    IMAGE_SECTION_HEADER* sect = IMAGE_FIRST_SECTION(nth);
    for (unsigned i = 0; i < nth->FileHeader.NumberOfSections; ++i) {
        uint8_t* dest = imageBase + sect[i].VirtualAddress;
        uint8_t* srcSec = (uint8_t*)src + sect[i].PointerToRawData;
        SIZE_T copySize = min((SIZE_T)sect[i].SizeOfRawData, (SIZE_T)sect[i].Misc.VirtualSize);
        if (copySize && (SIZE_T)sect[i].PointerToRawData + copySize <= srcSize) {
            memcpy(dest, srcSec, copySize);
        }
        else {
            // Zero remainder
            SIZE_T vsz = sect[i].Misc.VirtualSize;
            if (vsz) memset(dest, 0, vsz);
        }
    }

    // Perform base relocations if needed
    intptr_t delta = (intptr_t)(imageBase - (uint8_t*)opt.ImageBase);
    if (delta != 0 && opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto reloc = (IMAGE_BASE_RELOCATION*)(imageBase + opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        SIZE_T relocSize = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        SIZE_T processed = 0;
        while (processed < relocSize && reloc->SizeOfBlock) {
            DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* list = (WORD*)((uint8_t*)reloc + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD i = 0; i < count; ++i) {
                WORD entry = list[i];
                WORD type = entry >> 12;
                WORD offset = entry & 0x0FFF;
                if (type == IMAGE_REL_BASED_DIR64) {
                    uint64_t* addr = (uint64_t*)(imageBase + reloc->VirtualAddress + offset);
                    *addr = (uint64_t)(*addr + delta);
                }
                else if (type == IMAGE_REL_BASED_HIGHLOW) {
                    uint32_t* addr = (uint32_t*)(imageBase + reloc->VirtualAddress + offset);
                    *addr = (uint32_t)(*addr + (uint32_t)delta);
                }
                else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                    // skip
                }
                else {
                    // other types ignored in simple loader
                }
            }
            processed += reloc->SizeOfBlock;
            reloc = (IMAGE_BASE_RELOCATION*)((uint8_t*)reloc + reloc->SizeOfBlock);
        }
    }

    // Resolve imports
    if (opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto importDesc = (IMAGE_IMPORT_DESCRIPTOR*)(imageBase + opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (importDesc->Name) {
            char* dllName = (char*)(imageBase + importDesc->Name);
            HMODULE hMod = LoadLibraryA(dllName);
            if (!hMod) { VirtualFree(imageBase, 0, MEM_RELEASE); return nullptr; }
            IMAGE_THUNK_DATA* thunkILT = (IMAGE_THUNK_DATA*)(imageBase + importDesc->OriginalFirstThunk);
            IMAGE_THUNK_DATA* thunkIAT = (IMAGE_THUNK_DATA*)(imageBase + importDesc->FirstThunk);
            if (!importDesc->OriginalFirstThunk) thunkILT = thunkIAT; // some binaries omit OriginalFirstThunk
            while (thunkILT->u1.AddressOfData) {
                FARPROC func = nullptr;
                if (thunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    // import by ordinal
                    DWORD ord = IMAGE_ORDINAL(thunkILT->u1.Ordinal);
                    func = GetProcAddress(hMod, reinterpret_cast<LPCSTR>(static_cast<ULONG_PTR>(ord)));
                }
                else {
                    IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(imageBase + thunkILT->u1.AddressOfData);
                    func = GetProcAddress(hMod, ibn->Name);
                }
                if (!func) { VirtualFree(imageBase, 0, MEM_RELEASE); return nullptr; }
                thunkIAT->u1.Function = (ULONGLONG)func;
                ++thunkILT; ++thunkIAT;
            }
            ++importDesc;
        }
    }

    // Set final protections for sections
    for (unsigned i = 0; i < nth->FileHeader.NumberOfSections; ++i) {
        uint8_t* secAddr = imageBase + sect[i].VirtualAddress;
        SIZE_T secSize = max((SIZE_T)sect[i].Misc.VirtualSize, (SIZE_T)1);
        DWORD protect = PAGE_NOACCESS;
        bool isExec = (sect[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        bool isRead = (sect[i].Characteristics & IMAGE_SCN_MEM_READ) != 0;
        bool isWrite = (sect[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        if (isExec) {
            if (isRead) protect = isWrite ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
            else protect = isWrite ? PAGE_EXECUTE_WRITECOPY : PAGE_EXECUTE;
        }
        else {
            if (isRead) protect = isWrite ? PAGE_READWRITE : PAGE_READONLY;
            else protect = isWrite ? PAGE_WRITECOPY : PAGE_NOACCESS;
        }
        DWORD old;
        VirtualProtect(secAddr, secSize, protect, &old);
    }

    // Run TLS callbacks if present
    if (opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto tls = (IMAGE_TLS_DIRECTORY*)(imageBase + opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
#ifdef _WIN64
        PIMAGE_TLS_DIRECTORY64 tls64 = (PIMAGE_TLS_DIRECTORY64)tls;
        auto callbacks = (PIMAGE_TLS_CALLBACK*)(tls64->AddressOfCallBacks);
#else
        PIMAGE_TLS_DIRECTORY32 tls32 = (PIMAGE_TLS_DIRECTORY32)tls;
        auto callbacks = (PIMAGE_TLS_CALLBACK*)(tls32->AddressOfCallBacks);
#endif
        if (callbacks) {
            for (size_t i = 0; callbacks[i]; ++i) {
                callbacks[i]((PVOID)imageBase, DLL_PROCESS_ATTACH, nullptr);
            }
        }
    }

    // Call entry point (DllMain)
    if (opt.AddressOfEntryPoint) {
        auto entry = (FARPROC)(imageBase + opt.AddressOfEntryPoint);
        typedef BOOL(WINAPI* DllEntry)(HINSTANCE, DWORD, LPVOID);
        DllEntry DllMain = (DllEntry)entry;
        // change protection for entry point region to be executable
        DWORD oldProt; VirtualProtect((LPVOID)entry, 1, PAGE_EXECUTE_READ, &oldProt);
        BOOL ok = DllMain((HINSTANCE)imageBase, DLL_PROCESS_ATTACH, nullptr);
        if (!ok) {
            VirtualFree(imageBase, 0, MEM_RELEASE);
            return nullptr;
        }
    }

    // Flush instruction cache for safety
    FlushInstructionCache(GetCurrentProcess(), imageBase, imageSize);

    return (HMODULE)imageBase;
}

HMODULE manual_map_from_file(const char* path) {
    auto buf = read_file_bytes(path);
    if (buf.empty()) return nullptr;
    return manual_map_from_memory((const uint8_t*)buf.data(), buf.size());
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <path-to-dll>\n";
        return 1;
    }
	std::cout << "Press Enter to load " << argv[1] << " via manual mapping...";
    std::cin.get();
    HMODULE h = manual_map_from_file(argv[1]);
    if (h) {
        std::cout << "Manual map succeeded: base= " << h << "\n";
    }
    else {
        std::cout << "Manual map failed\n";
    }
    std::cout << "Press Enter to exit...";
	std::cin.get();
    return 0;
}
