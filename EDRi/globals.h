#pragma once

#include <basetsd.h>
#include <string>
#include <vector>
#include <shared_mutex>

#include "helpers/json.hpp"
using json = nlohmann::json;

static const std::string EDRi_PROVIDER = "EDRi-Provider";
static const std::string HOOK_PROVIDER = "Hook-Provider"; // must the same in the other project
static const std::string ATTACK_PROVIDER = "Attack-Provider"; // must the same in the other project
static const int EDRi_PROVIDER_EVENT_ID = 4242;
static const int HOOK_PROVIDER_EVENT_ID = 7007;
static const int ATTACK_PROVIDER_EVENT_ID = 1337;

static const std::wstring EDRi_PROVIDER_GUID_W = L"{72248477-7177-4feb-a386-34d8f35bb637}";
static const std::string EDRi_TRACE_START_MARKER = "++ EDRi START MARKER ++";
static const std::string NTDLL_HOOKER_TRACE_START_MARKER = "++ NTDLL-HOOKER STARTED ++";

// executables used for the attack
static const std::string injected_exe = "whoami.exe";
static const std::string injected_path = "C:\\Windows\\System32\\" + injected_exe;
static const std::string invoked_name = "microsoft.windowscalculator"; // windows apps are like ...\WindowsApps\Microsoft.WindowsCalculator_.... in the logs

// executables to track for kernel event filtering, i.e. their PIDs at runtime
extern std::vector<std::string> g_exes_to_track;
extern std::vector<int> g_newly_hooked_procs;

// tracking data
struct ProcInfo {
	int PID;
	UINT64 start_time;
	UINT64 end_time;
	std::string name;
	bool to_track;
};
extern ProcInfo g_attack_proc;
extern ProcInfo g_injected_proc;
extern std::vector<ProcInfo> g_running_procs;
extern std::shared_mutex g_procs_mutex;

extern bool g_traces_started;
extern bool g_hooker_started;
extern bool g_attack_terminated;

extern bool g_debug;
extern bool g_super_debug;

extern std::string g_attack_exe_name;
extern std::string g_attack_exe_path;
