#pragma once

#include <vector>

static const std::vector<int> event_ids_to_remove = { 44, 62, 7 };

// event ids with X to filter for
static const std::vector<int> event_ids_with_pid = { 104, 105, 109, 11, 111, 112, 15, 16, 26, 29, 5, 6, 60, 70, 71, 72, 73 };
static const std::vector<int> event_ids_with_pid_or_tpid = { 53 };
static const std::vector<int> event_ids_with_pid_in_data = { 43, 67 };
static const std::vector<int> event_ids_with_message = { 3 };
static const std::vector<int> event_ids_with_filepath = { 30, 31, 35, 36, 37, 38 };

// TODO find a way to filter event 59