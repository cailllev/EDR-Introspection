#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>
#include <cctype>

// Inject DLL into target process
bool inject_dll(int pid, const std::string& dllPath)
{
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);

    if (!hProcess) {
        std::cerr << "[!] Hooker: Failed to open target process. Error: " << GetLastError() << "\n";
        return false;
    }

    // Allocate memory for DLL path in target
    size_t size = dllPath.length() + 1;
    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        std::cerr << "[!] Hooker: VirtualAllocEx failed. Error: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }

    // Write DLL path into target
    if (!WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), size, nullptr)) {
        std::cerr << "[!] Hooker: WriteProcessMemory failed. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Get LoadLibraryA address
    LPVOID loadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLibAddr || loadLibAddr == 0) {
        std::cerr << "[!] Hooker: GetProcAddress failed\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Create remote thread
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)loadLibAddr, remoteMem, 0, nullptr);

    if (!hThread) {
        std::cerr << "[!] Hooker: CreateRemoteThread failed. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    return true;
}

bool unload_dll(HANDLE hProcess, HANDLE hThread, LPVOID remoteMem){
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}
