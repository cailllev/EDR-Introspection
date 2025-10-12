#include <windows.h>
#include <winternl.h>
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

// Minimal OBJECT_BASIC_INFORMATION from winternl
typedef struct _OBJECT_BASIC_INFORMATION {
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG Reserved[10];
} OBJECT_BASIC_INFORMATION;

extern "C" NTSTATUS NTAPI NtQueryObject(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);

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
    OBJECT_BASIC_INFORMATION obi = {};
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

// Inject DLL into target process
bool inject_dll(int pid, const std::string& dllPath, bool debug)
{
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE, pid);

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

    // Allocate memory for DLL path in target
    size_t size = dllPath.length() + 1;
    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        std::cerr << "[!] Hooker: VirtualAllocEx failed. Error: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }
    if (debug) {
		std::cout << "[*] Hooker: Allocated memory in target process at " << remoteMem << "\n";
    }

    // Write DLL path into target
    if (!WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), size, nullptr)) {
        std::cerr << "[!] Hooker: WriteProcessMemory failed. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    if (debug) {
        std::cout << "[*] Hooker: Wrote DLL path to target process memory\n";
	}

    // Get LoadLibraryA address
    HMODULE lpModuleHandle = GetModuleHandleA("kernel32.dll");
    if (!lpModuleHandle) {
        std::cerr << "[!] Hooker: GetModuleHandle failed\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    LPVOID loadLibAddr = (LPVOID)GetProcAddress(lpModuleHandle, "LoadLibraryA");
    if (!loadLibAddr) {
        std::cerr << "[!] Hooker: GetProcAddress failed\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Create remote thread (start the DLL)
	HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLibAddr, remoteMem, 0, nullptr);
    DWORD err = GetLastError();
    if (!hThread || err != 0) {
        std::cerr << "[!] Hooker: CreateRemoteThread failed. Error: " << err << "\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    if (debug) {
        std::cout << "[*] Hooker: Created remote thread in target process\n";
	}

    return true;
}

bool unload_dll(HANDLE hProcess, HANDLE hThread, LPVOID remoteMem){
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}
