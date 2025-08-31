#pragma once

#include <vector>

static const int PROC_START_EVENT_ID = 73; // used for start proc tracking

static const std::vector<int> event_ids_to_remove = { 7, 44, 62 };

// event ids with X to filter for
static const std::vector<int> event_ids_with_pid = { 5, 6, 11, 15, 16, 26, 29, 104, 105, 109, 110, 111, 112, 60, 70, 71, 72, 73 };
static const std::vector<int> event_ids_with_pid_or_tpid = { 53 };
static const std::vector<int> event_ids_with_pid_in_data = { 43, 67 };
static const std::vector<int> event_ids_with_message = { 3 };
static const std::vector<int> event_ids_with_filepath = { 30, 31, 35, 36, 37, 38 };

// TODO find a way to filter event 59