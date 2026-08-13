#include <krabs.hpp>
#include "catch.hpp"

#include <Windows.h>
#include <string>
#include <iostream>
#include <vector>

#include "../InjectLoader/utils.h"
#include "../InjectLoader/hooker.h"
#include "test_utils.h"


const std::string testDll = "TestDLL.dll";
const std::string testDllPath = GetCurrentExePath() + "TestDLL.dll"; // relative path to the DLL to inject
const std::string testExe = "TestEXE.exe";

class TestProcess {
private:
    DWORD explorerPid = GetProcessIdByName(L"explorer.exe");
	std::string szExplorerPid = std::to_string(explorerPid);
    HANDLE hTriggerEvent = CreateEventA(
        NULL, FALSE, FALSE, ("Local\\TestEXE_OpenProc_" + szExplorerPid).c_str()
    );

public:
    PROCESS_INFORMATION pi{ 0 };
    DWORD pid = 0;
    HANDLE hProcess = NULL;

    TestProcess() = default;

	// starts the TestEXE process and returns true if exe is running, false if failed
    bool Start() {
        if (!hTriggerEvent) {
            std::cerr << "[!] TestProcess: Failed to create event signals. Error: " << GetLastError() << "\n";
            return false;
        }

        STARTUPINFOA si = { 0 };
        si.cb = sizeof(si);
		std::string szCmdLine = testExe + " " + szExplorerPid + " 1";
        char* cmdLine = const_cast<char*>(szCmdLine.c_str());

        BOOL result = CreateProcessA(
            NULL,            // Application name
            cmdLine,         // Command line (use standard application search order, Tests.exe and TestEXE.exe in same dir)
            NULL,            // Process security attributes
            NULL,            // Thread security attributes
            FALSE,           // Inherit handles
            0,               // Creation flags
            NULL,            // Environment
            NULL,            // Current directory
            &si,             // Startup info
            &pi              // Process information (out)
        );
        if (result == FALSE) {
            std::cerr << "[!] TestProcess: Failed to start test process. Error: " << GetLastError() << "\n";
            return FALSE;
        }

        pid = pi.dwProcessId;
        hProcess = pi.hProcess;
        Sleep(500); // let the new process cook for a while

        return TRUE;
    }

    // Signals TestEXE to run OpenProcess and waits for the _done event
    bool TriggerAction(DWORD timeoutMs = 5000) {
        if (!hTriggerEvent) return false;
        SetEvent(hTriggerEvent);
        return true;
    }

    DWORD GetExplorerPid() {
        return explorerPid;
    }

    // RAII Destructor: Automatically terminates process on scope exit or REQUIRE failure
    ~TestProcess() {
        if (hProcess) {
            if (!TerminateProcess(hProcess, 0)) {
                std::cerr << "[!] TestProcess: Failed to stop test process. Error: " << GetLastError() << "\n";
            }
            CloseHandle(hProcess);
        }
        if (pi.hThread) {
            CloseHandle(pi.hThread);
        }
    }

    // Prevent accidental copying
    TestProcess(const TestProcess&) = delete;
    TestProcess& operator=(const TestProcess&) = delete;
};

TEST_CASE("findProcHandle - Process Handle Table Query", "[utils][handles]") {

    SECTION("Returns NULL when no matching handle exists in local process") {
		SUCCEED("Starting findProcHandle negative test..."); // forces the section header to print)

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

enum DllLoadedVerification {
    RemoteModuleHandle,
	RemoteManualMappedModule
 };

void ResetEtwEvent() {
    g_lastEvent = { "", 0, 0 };
    if (g_hEtwEvent) {
        ResetEvent(g_hEtwEvent);
    }
}

void TestDllInjection(Action injectionType, Execution execType, DllLoadedVerification verificationType, BOOL debug) {
	std::string injTypeStr = GetActionStr(injectionType);
	std::string execTypeStr = GetExecutionStr(execType);

	SECTION("Successfully injects a DLL with " + injTypeStr + " and " + execTypeStr) {
        SUCCEED("Starting injection test..."); // forces the section header to print

		// start test process and reset event
		TestProcess p;
		REQUIRE(p.Start());
        ResetEtwEvent();

		// inject the test DLL into the current process
		bool injected = InjectDll(p.pid, testDllPath, debug, injectionType, NULL, execType);
		Sleep(100); // wait for prints
		REQUIRE(injected == true);

		// verify that the startup event is caught
		REQUIRE(WaitForEtwEvent(3000, p.pid, "Hooks installed"));

		// then verify also that the DLL it is loaded
        switch (verificationType) {
        case RemoteModuleHandle: {
            HMODULE hLoaded = GetRemoteModuleHandle(p.pid, testDll);
            REQUIRE(hLoaded != NULL);
            break;
        }
        case RemoteManualMappedModule: {
            HMODULE hLoaded = GetRemoteManualMappedModule(p.hProcess, testDll);
            REQUIRE(hLoaded != NULL);
            break;
        }
        default:
            std::cerr << "[!] TestDllInjection: Unknown verification type.\n";
			REQUIRE(FALSE); // Force test failure for unknown verification type
            break;
        }

        Sleep(100); // wait a bit for reset
        ResetEtwEvent();
        Sleep(100); // wait a bit for reset

		// send the OpenProcess signal and verify that the NtOpenProcess hook was triggered and captured
		p.TriggerAction();
        REQUIRE(WaitForEtwEvent(3000, p.GetExplorerPid(), "NtOpenProcess with access 0x1fffff"));
	}
}

TEST_CASE("InjectDll - DLL Injection Verification", "[loader][inject]") {
    BOOL debug = TRUE;
	TestDllInjection(LOADLIBRARY_INJECTION, CREATE_REMOTE_THREAD, RemoteModuleHandle, debug);
	TestDllInjection(EXTERNAL_INJECTION, CREATE_REMOTE_THREAD, RemoteManualMappedModule, debug);
	TestDllInjection(EXTERNAL_INJECTION, HIJACK_THREAD, RemoteManualMappedModule, debug);
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
        REQUIRE(result == TRUE);

        // 4. Verify the DLL is no longer mapped in memory
        HMODULE hCheckAfter = GetModuleHandleA(testDllName);
        REQUIRE(hCheckAfter == NULL);
    }

    SECTION("Successfully unloads a manually loaded DLL") {
        // 1. Manually load a standard Windows DLL into the current process
        //HMODULE hLoaded = InjectDll();
    }
}