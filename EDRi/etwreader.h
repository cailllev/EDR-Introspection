#pragma once

#include <vector>


bool start_etw_traces(std::vector<HANDLE>& threads);
bool start_etw_ti_traces(std::vector<HANDLE>& threads);
void stop_all_etw_traces();
