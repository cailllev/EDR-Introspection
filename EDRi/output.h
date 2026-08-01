#pragma once

#include <map>
#include <string>
#include <vector>

#include "helpers/json.hpp"

#include "filter.h"

void print_etw_counts(std::vector<json>&);
void print_time_differences();
void dump_signatures(std::vector<json>&, std::string);

// CSV OUTPUT
void build_device_map();
void write_events_to_file(std::vector<json>&, const std::string&, bool);