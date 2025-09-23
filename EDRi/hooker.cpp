#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>
#include <cctype>

bool enable_debug_privilege()
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed: " << GetLastError() << "\n";
        return false;
    }

    TOKEN_PRIVILEGES tp = { 0 };
    LUID luid;
    if (!LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &luid)) {
        std::cerr << "LookupPrivilegeValueA failed: " << GetLastError() << "\n";
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
        std::cerr << "AdjustTokenPrivileges failed: " << GetLastError() << "\n";
        CloseHandle(hToken);
        return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "SeDebugPrivilege not assigned to this token\n";
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

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

    // Allocate memory for DLL path in target
    size_t size = dllPath.length() + 1;
    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        std::cerr << "[!] Hooker: VirtualAllocEx failed. Error: " << GetLastError() << "\n";
		std::cout << "[+] Hooker: Trying to enable SeDebugPrivilege and retry...\n";
        if (!enable_debug_privilege()) {
            std::cerr << "[!] Hooker: Failed to enable SeDebugPrivilege\n";
            return false;
        }
        // try again
        remoteMem = VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteMem) {
            std::cerr << "[!] Hooker: VirtualAllocEx failed again! Error: " << GetLastError() << "\n";
            CloseHandle(hProcess);
            return false;
        }
    }

    // Write DLL path into target
    if (!WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), size, nullptr)) {
        std::cerr << "[!] Hooker: WriteProcessMemory failed. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Get LoadLibraryA address
    HMODULE lpModuleHandle = GetModuleHandleA("kernel32.dll");
    LPVOID loadLibAddr = (LPVOID)GetProcAddress(lpModuleHandle, "LoadLibraryA");
    if (!loadLibAddr) {
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
