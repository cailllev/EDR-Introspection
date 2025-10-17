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
            krabs::parser parser(schema);

            std::wcout << L"PID: " << record.EventHeader.ProcessId << L" : " << std::wstring(schema.task_name()) << std::endl;

            for (const auto& prop : parser.properties()) {
                const std::wstring& name = prop.name();
                const auto type = prop.type();

                std::wcout << "  " << prop.name() << ": ";
                try {
                    switch (prop.type()) {
                    case TDH_INTYPE_INT32: std::cout << (int32_t)parser.parse<int32_t>(name); break;
                    case TDH_INTYPE_UINT32: std::cout << (uint32_t)parser.parse<uint32_t>(name); break;
                    case TDH_INTYPE_INT64: std::cout << (int64_t)parser.parse<int64_t>(name); break;
                    case TDH_INTYPE_UINT64: std::cout << (uint64_t)parser.parse<uint64_t>(name); break;
                    case TDH_INTYPE_POINTER: std::cout << (uint64_t)parser.parse<PVOID>(name); break;
                    case TDH_INTYPE_ANSISTRING: std::cout << parser.parse<std::string>(name); break;
                    default: std::cout << "<unsupported type>"; break;
                    }
                }
                catch (...) {
                    std::cout << "<error reading>";
                }
                std::cout << std::endl;
            }
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