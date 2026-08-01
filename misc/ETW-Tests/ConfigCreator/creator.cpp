#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <fstream>
#include <regex>

static std::string Utf16ToUtf8(const std::wstring& w) {
    return std::string(w.begin(), w.end());
}

struct ProviderInfo {
    std::string name;
    std::string guid;
};

static DWORD GetPIDByName(const std::wstring& exeName) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exeName.c_str()) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &pe));
    }
    CloseHandle(snapshot);
    return pid;
}

static std::wstring RunCommand(const std::wstring& cmd) {
    std::wstring result;
    // L"r" for modern MSVC.
    FILE* pipe = _wpopen(cmd.c_str(), L"r");
    if (!pipe) return result;

    wchar_t buffer[4096];
    while (fgetws(buffer, static_cast<int>(std::size(buffer)), pipe)) {
        result += buffer;
    }
    _pclose(pipe);
    return result;
}

static std::vector<ProviderInfo> ParseProviders(const std::wstring& logmanOutput) {
    std::vector<ProviderInfo> providers;
    // Matches lines like: "Provider Name                  {12345678-1234-1234-1234-1234567890AB}"
    std::wregex pattern(LR"((.*?)\s+\{([0-9A-Fa-f\-]+)\})");
    std::wsmatch match;

    std::wstringstream ss(logmanOutput);
    std::wstring line;
    while (std::getline(ss, line)) {
        if (std::regex_search(line, match, pattern)) {
            ProviderInfo info;
            // trim leading/trailing whitespace from name
            std::wstring name = match[1].str();
            size_t start = name.find_first_not_of(L" \t\r\n");
            size_t end = name.find_last_not_of(L" \t\r\n");
            if (start == std::wstring::npos) name.clear();
            else name = name.substr(start, end - start + 1);

            info.name = Utf16ToUtf8(name);
            info.guid = Utf16ToUtf8(match[2].str());
            providers.push_back(std::move(info));
        }
    }
    return providers;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc != 3) {
        std::wcerr << L"Usage: ConfigCreator.exe <exe name > <monitored exe path>\n";
        std::wcerr << L"Example: ConfigCreator.exe MsMpEng.exe C:\\Users\\Public\\Downloads\\mal.exe\n";
        return 1;
    }
    std::wstring exeName = argv[1];
    std::wstring secondExePath = argv[2];

    // find PID by executable name
    DWORD pid1 = GetPIDByName(exeName);
    if (pid1 == 0) {
        std::wcerr << L"Could not find running process: " << exeName << L"\n";
        return 1;
    }
    std::wcout << L"[>] PID of " << exeName << L": " << pid1 << L"\n";

    // run logman for PID
    std::wstring cmd = L"logman.exe query providers -pid " + std::to_wstring(pid1);
    std::wstring logmanOutput = RunCommand(cmd);

    // parse provider GUIDs
    auto providers = ParseProviders(logmanOutput);
    if (providers.empty()) {
        std::wcerr << L"No providers parsed from logman output.\n";
        return 1;
    }
    std::wcout << L"[>] Providers found: " << providers.size() << L"\n";

    // launch second executable and get its PID
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(
        secondExePath.c_str(), nullptr, nullptr, nullptr, FALSE,
        0, nullptr, nullptr, &si, &pi)) {
        std::wcerr << L"Failed to start: " << secondExePath << L" (err=" << GetLastError() << L")\n";
        return 1;
    }
    DWORD pid2 = pi.dwProcessId;
    std::wcout << L"[>] Launched process PID: " << pid2 << L"\n";
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    // build JSON and write to file
    std::ostringstream json;
    json << "{\n";
    json << "  \"session_properties\": {\n";
    json << "    \"session_name\": \"MyEDRTracer\",\n";
    json << "    \"output_format\": \"stdout\",\n";
    json << "    \"buffering_timout_seconds\": 10\n"; // keeping user's key spelling
    json << "  },\n";
    json << "  \"user_traces\": [\n";

    for (size_t i = 0; i < providers.size(); ++i) {
        json << "    {\n";
        json << "      \"trace_name\": \"ProcTrace\"" << i << ",\n";
        // Spec says: provider_name -> GUID from step 4
        json << "      \"provider_name\": \"" << providers[i].guid << "\",\n";
        json << "      \"filters\": {\n";
        json << "        \"all_of\": {\n";
        json << "          \"process_id_is\": " << pid1 << ",\n";
        json << "          \"property_is\": {\n";
        json << "            \"name\": \"TargetPID\",\n";
        json << "            \"value\": " << pid2 << ",\n";
        json << "            \"type\": \"UINT32\"\n";
        json << "          }\n";
        json << "        }\n";
        json << "      }\n";
        json << "    }";
        if (i + 1 < providers.size()) json << ",";
        json << "\n";
    }

    json << "  ]\n";
    json << "}\n";

    std::ofstream out("config.json", std::ios::binary);
    const std::string payload = json.str();
    out.write(payload.data(), static_cast<std::streamsize>(payload.size()));
    out.close();

    std::wcout << L"[>] JSON written to providers.json\n";
    return 0;
}