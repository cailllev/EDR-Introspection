#pragma once

#include <map>

#include "helpers/json.hpp"


static const std::wstring EDRi_PROVIDER_GUID_W = L"{72248477-7177-4feb-a386-34d8f35bb637}";

extern int g_attack_PID;
extern int g_injected_PID;

extern std::map<int, std::string> g_running_procs;

extern bool g_debug;
extern bool g_super_debug;

extern std::string attack_exe_path;
extern std::string attack_exe_enc_path;

using json = nlohmann::json;