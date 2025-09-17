#pragma once

#include <map>
#include <shared_mutex>

#include "helpers/json.hpp"

static const std::string EDRi_PROVIDER_NAME = "EDRi-Provider";
static const int EDRi_PROVIDER_EVENT_ID = 4242;
static const int ATTACK_PROVIDER_EVENT_ID = 1337;

static const std::wstring EDRi_PROVIDER_GUID_W = L"{72248477-7177-4feb-a386-34d8f35bb637}";
static const std::string EDRi_TRACE_START_MARKER = "[+] EDRi START MARKER";

extern std::vector<int> g_tracking_PIDs;
extern int g_attack_PID;
extern int g_injected_PID;

extern std::map<int, std::string> g_running_procs;
extern std::shared_mutex g_procs_mutex;

extern bool g_traces_started;
extern bool g_attack_terminated;

extern bool g_debug;
extern bool g_super_debug;

extern std::string attack_exe_path;
extern std::string attack_exe_enc_path;

using json = nlohmann::json;