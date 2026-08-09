#include "catch.hpp"
#include <Windows.h>
#include <tlhelp32.h>
#include <string>

#include "../InjectLoader/utils.h"
#include "../EDRiShared/hooker.h"

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

// starts a process for testing purposes and returns its PROCESS_INFORMATION, PID, and handle
void StartTestProcess(const std::wstring& exePath, PROCESS_INFORMATION& pi, DWORD& pid, HANDLE& hProcess) {
	STARTUPINFOW si = { 0 };
	si.cb = sizeof(si);
	BOOL result = CreateProcessW(
		exePath.c_str(), // Application name
		NULL,            // Command line
		NULL,            // Process security attributes
		NULL,            // Thread security attributes
		FALSE,           // Inherit handles
		0,               // Creation flags
		NULL,            // Environment
		NULL,            // Current directory
		&si,             // Startup info
		&pi              // Process information (out)
	);
    REQUIRE(result == TRUE);

    pid = pi.dwProcessId;
	hProcess = pi.hProcess;
}

// stops a test process
BOOL StopTestProcess(PROCESS_INFORMATION& pi) {
	if (pi.hProcess) {
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
	}
	if (pi.hThread) {
		CloseHandle(pi.hThread);
	}
	return TRUE;
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
		REQUIRE(hFound == hExplorer);

        // Clean up
        CloseHandle(hExplorer);
    }
}

TEST_CASE("InjectDll - DLL Injection Verification", "[loader][inject]") {

    DWORD pid = 0;
	HANDLE hProcess = NULL;
	PROCESS_INFORMATION pi = { 0 };

    bool debug = true;
	const char* testDllPath = "C:\\Windows\\System32\\version.dll";

	SECTION("Successfully injects a DLL into the current process with LoadLibrary and CreateRemoteThread") {
        // 0. Start test process
        StartTestProcess(L"C:\\Windows\\System32\\notepad.exe", pi, pid, hProcess);

		// 1. Inject a standard Windows DLL into the current process
		bool injected = InjectDll(pid, testDllPath, debug, LOADLIBRARY_INJECTION, NULL, CREATE_REMOTE_THREAD);
		REQUIRE(injected == true);

        Sleep(2000); // the loading is threaded

		// 2. Verify it is loaded using native Win32 API
		HMODULE hLoaded = GetRemoteModuleHandle(pid, L"version.dll");
		REQUIRE(hLoaded != NULL);

		// 3. Stop test process
		StopTestProcess(pi);
	}

    SECTION("Successfully injects a DLL into the current process with External Injection and CreateRemoteThread") {
		// 0. Start test process
        StartTestProcess(L"C:\\Windows\\System32\\notepad.exe", pi, pid, hProcess);

        // 1. Inject a standard Windows DLL into the current process
        bool injected = InjectDll(pid, testDllPath, debug, EXTERNAL_INJECTION, NULL, CREATE_REMOTE_THREAD);
        REQUIRE(injected == true);

        Sleep(2000); // safety wait (might not be needed)

        // 2. Verify it is loaded
        HMODULE hLoaded = GetRemoteManualMappedModule(hProcess, "version.dll");
        REQUIRE(hLoaded != NULL);

		// 3. Stop test process
		StopTestProcess(pi);
    }

	SECTION("Successfully injects a DLL into the current process with External Injection and HijackThread") {
        // 0. Start test process
        StartTestProcess(L"C:\\Windows\\System32\\notepad.exe", pi, pid, hProcess);

		// 1. Inject a standard Windows DLL into the current process
		bool injected = InjectDll(pid, testDllPath, debug, EXTERNAL_INJECTION, NULL, HIJACK_THREAD);
		REQUIRE(injected == true);

        // thread hijacking != immidiate execution, must find a way to trigger execution or poll until successful
        Sleep(2000); // todo

		// 2. Verify it is loaded using snapshot enumeration
		HMODULE hLoaded = GetRemoteModuleHandle(pid, L"version.dll");
		REQUIRE(hLoaded != NULL);

        // 3. Stop test process
        StopTestProcess(pi);
	}
}

TEST_CASE("Unload - DLL Unload Verification", "[loader][unload]") {
    DWORD currentPid = GetCurrentProcessId();
    const char* testDllName = "version.dll";

    SECTION("Successfully unloads a DLL loaded via LoadLibrary") {
        // 1. Load a standard Windows DLL into the current process
        HMODULE hLoaded = LoadLibraryA(testDllName);
        REQUIRE(hLoaded != NULL);

        // 2. Verify it is loaded using native Win32 API
        HMODULE hCheckBefore = GetModuleHandleA(testDllName);
        REQUIRE(hCheckBefore != NULL);
        REQUIRE(hCheckBefore == hLoaded);

        // 3. Call Unload()
        int result = UnloadViaThread(static_cast<int>(currentPid), testDllName);
        REQUIRE(result == 0);

        // 4. Verify the DLL is no longer mapped in memory
        HMODULE hCheckAfter = GetModuleHandleA(testDllName);
        REQUIRE(hCheckAfter == NULL);
    }

    SECTION("Successfully unloads a manually loaded DLL") {
        // 1. Manually load a standard Windows DLL into the current process
        //HMODULE hLoaded = InjectDll();
    }
}