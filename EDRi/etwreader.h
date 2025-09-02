#pragma once

#include <vector>


bool start_etw_traces(std::vector<HANDLE>& threads);
void stop_etw_traces();
