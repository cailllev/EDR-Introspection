#include "proc.h"

#include <core/pebwalker.h>
#include <libc/string.h>
#include <libc/wchar.h>

typedef HANDLE(WINAPI* OpenProcess_t)(DWORD, BOOL, DWORD);
typedef BOOL(WINAPI* CloseHandle_t)(HANDLE);
typedef HANDLE(WINAPI* CreateToolhelp32Snapshot_t)(DWORD, DWORD);
typedef BOOL(WINAPI* Process32FirstW_t)(HANDLE, LPPROCESSENTRY32W);
typedef BOOL(WINAPI* Process32NextW_t)(HANDLE, LPPROCESSENTRY32W);

// Resolve a kernel32 export using your PEB walker
static void* resolve_kernel32(const char* name)
{
    HMODULE k32 = GetDllFromMemory(L"kernel32.dll");
    if (!k32)
        return NULL;

    return GetProcAddr(k32, name);
}

// Wrapper for OpenProcess
MODULE HANDLE open_process_pic(DWORD pid)
{
    OpenProcess_t fn = (OpenProcess_t)resolve_kernel32("OpenProcess");
    if (!fn)
        return NULL;

    return fn(PROCESS_ALL_ACCESS, FALSE, pid);
}

// Wrapper for CloseHandle
MODULE BOOL close_handle_pic(HANDLE h)
{
    CloseHandle_t fn = (CloseHandle_t)resolve_kernel32("CloseHandle");
    if (!fn)
        return FALSE;

    return fn(h);
}

// Convert ASCII -> Wide string (PIC-safe)
static void ascii_to_wide(const char* src, wchar_t* dst, size_t max)
{
    size_t i = 0;
    for (; i < max - 1 && src[i] != 0; i++)
        dst[i] = (wchar_t)src[i];
    dst[i] = 0;
}

// Main function: find PID by name and open process
MODULE HANDLE open_process_by_name_pic(const char* name)
{
    // Resolve required Toolhelp functions
    CreateToolhelp32Snapshot_t pSnap =
        (CreateToolhelp32Snapshot_t)resolve_kernel32("CreateToolhelp32Snapshot");
    Process32FirstW_t pFirst =
        (Process32FirstW_t)resolve_kernel32("Process32FirstW");
    Process32NextW_t pNext =
        (Process32NextW_t)resolve_kernel32("Process32NextW");
    CloseHandle_t pClose =
        (CloseHandle_t)resolve_kernel32("CloseHandle");

    if (!pSnap || !pFirst || !pNext || !pClose)
        return NULL;

    // Make a wildcard snapshot of all processes
    HANDLE snapshot = pSnap(0x00000002 /* TH32CS_SNAPPROCESS */, 0);
    if (!snapshot || snapshot == (HANDLE)-1)
        return NULL;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    wchar_t nameW[260];
    ascii_to_wide(name, nameW, 260);

    HANDLE result = NULL;

    if (pFirst(snapshot, &pe)) {
        do {
            if (wcscmp(pe.szExeFile, nameW) == 0) {
                // Found process — now open it with our existing wrapper
                result = open_process_pic(pe.th32ProcessID);
                break;
            }
        } while (pNext(snapshot, &pe));
    }

    pClose(snapshot);
    return result;
}
