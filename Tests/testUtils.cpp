#include <krabs.hpp>
#include "catch.hpp"

#include <tlhelp32.h>
#include <iostream>
#include <thread>
#include <chrono>

#include "testUtils.h"


static const std::wstring etwProvider = L"{72248411-7166-4feb-a386-34d8f35bb637}";
static const std::wstring etwSessionName = L"CaptureETWMessagesTrace";
std::unique_ptr<krabs::user_trace> g_trace;
std::thread g_traceThread;
std::unique_ptr<krabs::provider<>> g_provider; // must also be global to avoid being destroyed before the trace is stopped

uint64_t GetTimeNowNs() {
	return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

uint64_t timeStartNs = GetTimeNowNs();
TestETWEvent g_lastEvent = {};
HANDLE g_hEtwEvent = CreateEventA(NULL, FALSE, FALSE, NULL); // FALSE = auto-reset, FALSE = initially unsignaled

// wait X ms for next ETW event and check if matches the expected values
BOOL WaitForEtwEvent(DWORD timeoutMs, DWORD expectedTargetPid, std::string expectedMessage) {
    DWORD res = WaitForSingleObject(g_hEtwEvent, timeoutMs);
	if (res != WAIT_OBJECT_0) {
		std::cerr << "[!] Utils: WaitForEtwEvent timed out after " << timeoutMs << " ms\n";
        FAIL("Timed out waiting for ETW event");
		return FALSE;
	}

    REQUIRE(g_lastEvent.NsSinceEpoch >= timeStartNs);
	REQUIRE(g_lastEvent.targetPid == expectedTargetPid);
	REQUIRE(g_lastEvent.message == expectedMessage);

    return TRUE;
}

// gets the "\path\to\current\executable\directory\"
std::string GetCurrentExePath() {
	char buffer[MAX_PATH];
	DWORD length = GetModuleFileNameA(NULL, buffer, MAX_PATH);
	if (length == 0 || length == MAX_PATH) {
		std::cerr << "[!] Utils: Failed to get current executable path. Error: " << GetLastError() << "\n";
		return "";
	}
	std::string fullPath(buffer, length);
	size_t lastSlash = fullPath.find_last_of("\\/");
	if (lastSlash != std::string::npos) {
		return fullPath.substr(0, lastSlash + 1); // include the slash
	}
	return "";
}

// test dll emits etw messages when loaded, check it
void StartETWCapture() {

	// stop old sessions from previous runs, if any
    try {
        krabs::user_trace old_trace(etwSessionName);
        old_trace.stop();
    }
    catch (const std::exception& e) {
        std::cerr << "[!] Utils: ETW Trace Exception when stopping old trace: " << e.what() << "\n";
    }

    krabs::guid provider_guid(etwProvider);
    g_provider = std::make_unique<krabs::provider<>>(provider_guid);

    // Callback to dump all event fields
    g_provider->add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& ctx) {

        try {
            krabs::schema schema(record, ctx.schema_locator);

            // custom parsing when not using manifest based ETW --> cannot use property parsing
            const BYTE* data = (const BYTE*)record.UserData;
            ULONG size = record.UserDataLength;

            // PARSE MESSAGE
            const char* msg = reinterpret_cast<const char*>(data); // read until first null byte
            size_t msg_len = strnlen(msg, size);
            const BYTE* ptr_field = data + msg_len + 1;

            // PARSE NS_SINCE_EPOCH
            UINT64 ns_since_epoch = 0;
            if (ptr_field + sizeof(UINT64) <= data + size) {
                memcpy(&ns_since_epoch, ptr_field, sizeof(UINT64));
                ptr_field += sizeof(UINT64);
            }

            // PARSE TARGETPID
            uint64_t targetpid = static_cast<uint64_t>(-1);
            if (ptr_field + sizeof(uint64_t) <= data + size) {
                uint64_t tmp;
                memcpy(&tmp, ptr_field, sizeof(tmp));
                targetpid = tmp;
                ptr_field += sizeof(uint64_t);
            }

            g_lastEvent = { std::string(msg, msg_len), ns_since_epoch, targetpid };
            SetEvent(g_hEtwEvent); // wake up the test thread
			std::cout << "[*] Utils: New ETW Event at " << ns_since_epoch << " in " << targetpid << ": " << msg << "\n";
        }
        catch (const std::exception& e) {
            std::cerr << "[!] Utils: ETW Trace Exception: " << e.what() << "\n";
        }
    });

    // Trace session
    g_trace = std::make_unique<krabs::user_trace>(etwSessionName);
    g_trace->enable(*g_provider);

    // Launch in background thread so it doesn't block tests
    g_traceThread = std::thread([]() {
        try {
            g_trace->start();
        }
        catch (const std::exception& e) {
            std::cerr << "[!] Utils: ETW Trace Exception when starting: " << e.what() << "\n";
        }
    });
    std::cout << "[*] Utils: ETW trace started...\n";
}

void StopETWCapture() {
    if (g_trace) {
        g_trace->stop();
        if (g_traceThread.joinable()) {
            g_traceThread.join();
        }
    }
    std::cout << "[*] Utils: ETW trace stopped...\n";
}

DWORD GetProcessIdByName(const std::wstring& processName) {
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