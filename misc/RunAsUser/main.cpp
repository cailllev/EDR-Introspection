#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

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

DWORD get_explorer_pid() {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);

    if (Process32First(snap, &pe)) {
        do {
            if (std::strcmp(wchar2string(pe.szExeFile).c_str(), "explorer.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: RunAsUser.exe <full_path_to_exe>\n";
        return 1;
    }

    DWORD pid = get_explorer_pid();
    if (!pid) {
        std::cerr << "[!] No explorer.exe found. Is a user logged in?\n";
        return 1;
    }

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        std::cerr << "[!] Failed to open explorer.exe\n";
        return 1;
    }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
        CloseHandle(hProc);
        std::cerr << "[!] Failed to open explorer token\n";
        return 1;
    }
    CloseHandle(hProc);

    HANDLE hUserToken = NULL;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hUserToken)) {
        CloseHandle(hToken);
        std::cerr << "[!] Failed to duplicate token\n";
        return 1;
    }
    CloseHandle(hToken);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    BOOL ok = CreateProcessAsUserA(
        hUserToken,
        argv[1],
        NULL,
        NULL, NULL,
        FALSE,
        CREATE_NEW_CONSOLE,
        NULL, NULL,
        &si, &pi
    );

    if (!ok) {
        std::cerr << "[!] CreateProcessAsUserA failed: " << GetLastError() << "\n";
        CloseHandle(hUserToken);
        return 1;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hUserToken);

    std::cout << "[+] Started: " << argv[1] << " as explorer's user\n";
    return 0;
}
