#pragma once

#include <vector>

bool start_etw_default_traces(std::vector<HANDLE>& threads);
bool start_etw_misc_traces(std::vector<HANDLE>& threads);
bool start_etw_ti_trace(std::vector<HANDLE>& threads);
bool start_etw_hook_trace(std::vector<HANDLE>& threads);
void stop_all_etw_traces();
