#include "catch.hpp"
#include <Windows.h>
#include <tlhelp32.h>
#include <string>

#include "../InjectLoader/utils.h"

static DWORD GetProcessIdByName(const std::wstring& processName) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName.c_str()) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

TEST_CASE("Unload - DLL Unload Verification", "[loader][unload]") {
    DWORD currentPid = GetCurrentProcessId();
    const char* testDllName = "version.dll";

    SECTION("Successfully unloads a loaded module in the process") {
        // 1. Load a standard Windows DLL into the current process
        HMODULE hLoaded = LoadLibraryA(testDllName);
        REQUIRE(hLoaded != NULL);

        // 2. Verify it is loaded using native Win32 API
        HMODULE hCheckBefore = GetModuleHandleA(testDllName);
        REQUIRE(hCheckBefore != NULL);
        REQUIRE(hCheckBefore == hLoaded);

        // 3. Call Unload()
        int result = Unload(static_cast<int>(currentPid), testDllName);
        REQUIRE(result == 0);

        // 4. Verify the DLL is no longer mapped in memory
        HMODULE hCheckAfter = GetModuleHandleA(testDllName);
        REQUIRE(hCheckAfter == NULL);
    }
}

TEST_CASE("findProcHandle - Process Handle Table Query", "[utils][handles]") {

    SECTION("Returns NULL when no matching handle exists in local process") {
        // Querying for an invalid/non-existent PID returns NULL
        HANDLE hFound = findProcHandle(3, FALSE);
        REQUIRE(hFound == NULL);
    }

    SECTION("Finds a valid handle to explorer.exe in the local handle table") {
        // 1. Locate explorer.exe (running on almost all Windows desktop sessions)
        DWORD explorerPid = GetProcessIdByName(L"explorer.exe");
        REQUIRE(explorerPid != 0);

        // 2. Open a handle to explorer.exe to populate it in OUR handle table
        HANDLE hExplorer = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, explorerPid);
        REQUIRE(hExplorer != NULL);

        // 3. Verify findProcHandle locates the handle pointing to explorer.exe
        HANDLE hFound = findProcHandle(static_cast<int>(explorerPid), FALSE);
        REQUIRE(hFound != NULL);
		REQUIRE(hFound == hExplorer);

        // Clean up
        CloseHandle(hExplorer);
    }
}