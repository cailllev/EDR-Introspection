#pragma once

#include <map>
#include <string>
#include <vector>

#include "helpers/json.hpp"
#include "filter.h"

void clean_events(std::map<Classifier, std::vector<json>>&);
void print_etw_counts(std::map<Classifier, std::vector<json>>&);
void print_time_differences();
void dump_signatures(std::map<Classifier, std::vector<json>>&);

// CSV OUTPUT
void build_device_map();
void write_events_to_file(std::map<Classifier, std::vector<json>>&, const std::string&, bool);