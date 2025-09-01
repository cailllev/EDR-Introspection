#pragma once

#include <windows.h>

extern int g_EDR_PID;
extern int g_attack_PID;
extern int g_injected_PID;

extern std::map<int, std::string> g_running_procs;

extern bool g_trace_running;
extern bool g_attack_done;
extern bool g_debug;
extern bool g_super_debug;

extern std::vector<LONGLONG> g_usn;

using json = nlohmann::json;

extern std::string attack_exe_path;
extern std::string attack_exe_enc_path;