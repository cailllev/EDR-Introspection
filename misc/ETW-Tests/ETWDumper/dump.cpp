#include <krabs.hpp>
#include <nlohmann/json.hpp>
#include <iostream>
#include <vector>

// Convert wstring to string
std::string ws2s(const std::wstring& wstr) {
    return std::string(wstr.begin(), wstr.end());
}

// Convert byte vector to uint32
uint32_t byte2uint32(std::vector<BYTE> v) {
    uint32_t res = 0;
    for (int i = (int)v.size() - 1; i >= 0; i--) {
        res <<= 8;
        res += (uint32_t)v[i];
    }
    return res;
}

// Convert byte vector to uint64
uint64_t byte2uint64(std::vector<BYTE> v) {
    uint64_t res = 0;
    for (int i = 7; i >= 0; i--) {
        res <<= 8;
        res += (uint64_t)v[i];
    }
    return res;
}

// Callback function when session receives an event from provider
void callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    krabs::parser parser(schema);

    if (schema.event_id() == 1) {
        nlohmann::json data;
        data["ProcessID"] = byte2uint32(parser.parse<krabs::binary>(L"ProcessID").bytes());
        data["CreateTime"] = byte2uint64(parser.parse<krabs::binary>(L"CreateTime").bytes());
        data["ParentProcessID"] = byte2uint32(parser.parse<krabs::binary>(L"ParentProcessID").bytes());
        data["SessionID"] = byte2uint32(parser.parse<krabs::binary>(L"SessionID").bytes());
        data["ImageName"] = ws2s(parser.parse<std::wstring>(L"ImageName"));

        std::cout << data.dump(4) << std::endl;
    }
}

int main(int argc, const char* argv[]) {
    // Create an ETW session
    krabs::user_trace session(L"ETW_example");

    // Set provider
    std::wstring name = L"Microsoft-Antimalware-Engine";
    krabs::provider<> provider(name);
    provider.any(0x10);

    // Add event callback function
    provider.add_on_event_callback(callback);
	std::cout << "[>] Callback function added for provider: " << ws2s(name) << std::endl;

    // Enable provider and start session
    session.enable(provider);
    session.start();
}