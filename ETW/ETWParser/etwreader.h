#pragma once

#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

#include "globals.h"

bool start_etw_reader(std::vector<HANDLE>& threads);
void stop_etw_reader();
std::vector<std::string> get_events();

static const std::string TYPE = "type";
static const std::string TIMESTAMP = "timestamp";
static const std::string PID = "PID";
static const std::string TASK = "task";
static const std::string EVENT_ID = "event_id";
static const std::string PROVIDER_NAME = "provider_name";