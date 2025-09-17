#pragma once

#include <map>
#include <vector>
#include <string>


extern const std::map<std::string, std::vector<std::string>> edr_profiles;
std::string get_available_edrs();