#pragma once

#include <map>
#include <vector>
#include <string>


struct EDR_Profile {
    bool needs_kernel_callbacks_disabling;
    bool needs_minimal_hooks;
    std::vector<std::string> main_exes;
    std::vector<std::string> other_exes;
};
extern const std::map<std::string, EDR_Profile> edr_profiles;
std::string get_available_edrs();
std::vector<std::string> get_all_edr_exes(const EDR_Profile&);