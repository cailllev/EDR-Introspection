#pragma once

#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

#include "globals.h"

bool start_etw_reader(std::vector<HANDLE>& threads);
void stop_etw_reader();
std::vector<std::string> get_events();

std::string TYPE = "type";
std::string TIMESTAMP = "timestamp";
std::string PID = "PID";
std::string TASK = "task";
std::string EVENT_ID = "event_id";
std::string PROVIDER_NAME = "provider_name";