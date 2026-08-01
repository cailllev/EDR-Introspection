#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <string>

#pragma comment(lib, "ntdll.lib")

typedef struct _PROCESS_PROTECTION_LEVEL_INFORMATION {
    UCHAR ProtectionLevel;
} my_PROCESS_PROTECTION_LEVEL_INFORMATION;

typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

// helper to decode
std::string GetSignerName(UCHAR signer) {
    switch (signer) {
    case 0: return "None";
    case 1: return "Authenticode";
    case 2: return "CodeGen";
    case 3: return "Antimalware";
    case 4: return "Lsa";
    case 5: return "Windows";
    case 6: return "WinTcb";
    case 7: return "WinSystem";
    default: return "Unknown";
    }
}

std::string GetTypeName(UCHAR type) {
    switch (type) {
    case 0: return "None";
    case 1: return "Protected Light";
    case 2: return "Protected";
    case 3: return "Max";
    default: return "Unknown";
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Usage: pplQuery.exe <PID>\n";
        return 1;
    }

    DWORD pid = std::stoul(argv[1]);

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::cerr << "OpenProcess failed: " << GetLastError() << "\n";
        return 1;
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto NtQueryInformationProcess = (NtQueryInformationProcess_t)
        GetProcAddress(ntdll, "NtQueryInformationProcess");

    my_PROCESS_PROTECTION_LEVEL_INFORMATION info = { 0 };
    ULONG retLen = 0;

    NTSTATUS status = NtQueryInformationProcess(
        hProcess,
        (PROCESSINFOCLASS)61, // ProcessProtectionInformation
        &info,
        sizeof(info),
        &retLen
    );

    if (status != 0) {
        std::cerr << "NtQueryInformationProcess failed. NTSTATUS: 0x"
            << std::hex << status << "\n";
        CloseHandle(hProcess);
        return 1;
    }

    UCHAR prot = info.ProtectionLevel;
    UCHAR signer = prot >> 4;
    UCHAR type = prot & 0xF;

    std::cout << "PID " << pid << ":\n";
    if (prot == 0) {
        std::cout << "  Not protected (no PPL)\n";
    }
    else {
        std::cout << "  Signer: " << GetSignerName(signer) << " (" << (int)signer << ")\n";
        std::cout << "  Type:   " << GetTypeName(type) << " (" << (int)type << ")\n";
    }

    CloseHandle(hProcess);
    return 0;
}