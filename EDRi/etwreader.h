#pragma once

#include <vector>

static const std::wstring ETW_TI_PROVIDER_GUID_W = L"{b675ec37-bdb6-4648-bc92-f3fdc74d3ca2}";

bool start_etw_traces(std::vector<HANDLE>& threads);
bool start_etw_ti_traces(std::vector<HANDLE>& threads);
void stop_all_etw_traces();
