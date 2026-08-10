#include <krabs.hpp>

#include <iostream>
#include <vector>
#include <thread>

#include "test_utils.h"


static const std::wstring etwProvider = L"{72248411-7166-4feb-a386-34d8f35bb637}";
std::unique_ptr<krabs::user_trace> g_trace;
std::thread g_traceThread;

// test dll emits etw messages when loaded, check it
void StartETWCapture() {

    krabs::guid provider_guid(etwProvider);
    krabs::provider<> provider(provider_guid);

    // Callback to dump all event fields
    provider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& ctx) {

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

            capturedEvents.push_back({ std::string(msg, msg_len), ns_since_epoch, targetpid });
        }
        catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << "\n";
        }
    });

    // Trace session
    g_trace = std::make_unique<krabs::user_trace>(L"CaptureETWMessagesTrace");
    g_trace->enable(provider);

    // Launch in background thread so it doesn't block tests
    g_traceThread = std::thread([]() {
        try {
            g_trace->start();
        }
        catch (...) {}
    });
    std::cout << "[*] ETW trace started...\n";
}

void StopETWCapture() {
    if (g_trace) {
        g_trace->stop();
        if (g_traceThread.joinable()) {
            g_traceThread.join();
        }
    }
    std::cout << "[*] ETW trace stopped...\n";
}