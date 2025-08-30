#pragma once

#include <windows.h>

extern int g_EDR_PID;
extern int g_attack_PID;
extern int g_injected_PID;

extern bool g_trace_running;
extern bool g_attack_done;
extern bool g_debug;

extern std::vector<LONGLONG> g_usn;

using json = nlohmann::json;