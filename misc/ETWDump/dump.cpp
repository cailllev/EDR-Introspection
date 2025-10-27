#include <krabs.hpp> // must be before windows.h???

#include <windows.h>
#include <chrono>
#include <iostream>
#include <string>


std::string ns_to_iso8601(uint64_t ns_since_epoch)
{
    using namespace std::chrono;
    system_clock::duration duration = duration_cast<system_clock::duration>(nanoseconds(ns_since_epoch));
    system_clock::time_point time_point(duration);
    auto in_time_t = system_clock::to_time_t(time_point);
    auto fractional = duration_cast<nanoseconds>(time_point.time_since_epoch()) % 1'000'000'000;

    // Convert to UTC
    std::tm tm_buf;
    gmtime_s(&tm_buf, &in_time_t);

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S")
        << "." << std::setw(9) << std::setfill('0') << fractional.count()
        << "Z"; // UTC

    return oss.str();
}

int main(int argc, wchar_t* argv[]) {
    try {
        // Create provider
        //static const std::wstring provider_guid_str = L"{72248477-7177-4feb-a386-34d8f35bb637}"; // EDRi
        //static const std::wstring provider_guid_str = L"{72248466-7166-4feb-a386-34d8f35bb637}"; // attack
        static const std::wstring provider_guid_str = L"{72248411-7166-4feb-a386-34d8f35bb637}"; // Hooks
        krabs::guid provider_guid(provider_guid_str);
        krabs::provider<> provider(provider_guid);

        // Callback to dump all event fields
        provider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& ctx) {
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
            std::string iso_time = ns_to_iso8601(ns_since_epoch);

            // PARSE TARGETPID
            UINT64 targetpid = -1;
            if (ptr_field + sizeof(UINT64) <= data + size) {
                memcpy(&targetpid, ptr_field, sizeof(UINT64));
                ptr_field += sizeof(UINT64);
            }

            std::wcout << L"PID: " << record.EventHeader.ProcessId
                << L" : " << std::wstring(schema.task_name()) << std::endl;
            std::cout << "  message: " << msg << std::endl;
            std::cout << "  timestamp: " << iso_time << std::endl;
            std::cout << "  targetpid: " << targetpid << std::endl;
            std::cout << "--------------------------\n";
        });


        // Trace session
        krabs::user_trace trace(L"SimpleKrabsTrace");
        trace.enable(provider);

        std::wcout << L"[*] Listening to " << provider_guid_str << L"... Press Ctrl+C to exit" << std::endl;
        trace.start(); // blocks
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}