#include <krabs.hpp>
#include <iostream>
#include <string>
#include <windows.h>

int main(int argc, wchar_t* argv[]) {
    try {
        // Create provider
        static const std::wstring provider_guid_str = L"{72248411-7166-4feb-a386-34d8f35bb637}";
        krabs::guid provider_guid(provider_guid_str);
        krabs::provider<> provider(provider_guid);

        // Callback to dump all event fields
        provider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& ctx) {
            krabs::schema schema(record, ctx.schema_locator);

			// custom parsing when not using manifest based ETW --> cannot use property parsing
            const BYTE* data = (const BYTE*)record.UserData;
            ULONG size = record.UserDataLength;

            const char* msg = reinterpret_cast<const char*>(data); // read until first null byte
            size_t msg_len = strnlen(msg, size);

			const BYTE* pid_ptr = data + msg_len + 1; // get pointer to targetpid field
            uint64_t targetpid = 0;
			if (pid_ptr + sizeof(uint64_t) <= data + size) { // parse pid if still inside user data
                memcpy(&targetpid, pid_ptr, sizeof(uint64_t));
            }

            std::wcout << L"PID: " << record.EventHeader.ProcessId
                << L" : " << std::wstring(schema.task_name()) << std::endl;
            std::cout << "  message: " << msg << std::endl;
            std::cout << "  targetpid: " << targetpid << std::endl;
            std::cout << "--------------------------\n";
        });


        // Trace session
        krabs::user_trace trace(L"SimpleKrabsTrace");
        trace.enable(provider);

        std::cout << "[*] Listening... Press Ctrl+C to exit" << std::endl;
        trace.start(); // blocks
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}