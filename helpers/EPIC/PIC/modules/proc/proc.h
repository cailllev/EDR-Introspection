#pragma once
#include <epic.h>
#include <win32/windows.h>
#include <libc/stdint.h>

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef PROCESS_ALL_ACCESS
#define PROCESS_ALL_ACCESS 0x1F0FFF
#endif

// --- Toolhelp32 Snapshot Flags ---
#ifndef TH32CS_SNAPPROCESS
#define TH32CS_SNAPPROCESS 0x00000002
#endif

// --- PROCESSENTRY32W structure ---
typedef struct tagPROCESSENTRY32W {
    DWORD     dwSize;
    DWORD     cntUsage;
    DWORD     th32ProcessID;
    ULONG_PTR th32DefaultHeapID;
    DWORD     th32ModuleID;
    DWORD     cntThreads;
    DWORD     th32ParentProcessID;
    LONG      pcPriClassBase;
    DWORD     dwFlags;
    WCHAR     szExeFile[260];   // MAX_PATH
} PROCESSENTRY32W, * LPPROCESSENTRY32W;

MODULE HANDLE open_process_pic(DWORD pid);
MODULE HANDLE open_process_by_name_pic(const char* name);
MODULE BOOL   close_handle_pic(HANDLE h);