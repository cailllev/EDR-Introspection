#pragma once

#include <string>
#include <functional>

#include "globals.h"


static const int ANTIMALWARE_ATTACH_EVENT_ID = 4;
static const std::string ATTACH_EVENT_TASK = "Versions Info ";
static const std::string TERMINATION = "Termination";

class EdrProfile {
public:
    std::string edr_exe_name;
    bool started;

    std::function<void(const json&)> check_start;

    EdrProfile(std::string exe,
               std::function<bool(const json&, EdrProfile&)> start_filter)
        : edr_exe_name(exe), started(false)
    {
        check_start = [this, start_filter](const json& event) {
            if (!this->started && start_filter(event, *this)) {
                this->started = true;
                std::cout << "[+] Profile: Detected first Antimalware ETW event\n";
            }
        };
    }
};

std::string get_edr_profiles();
void set_edr_profile(std::string);
std::string get_edr_exe();
void edr_profile_check_start(json& ev);
bool edr_profile_is_trace_running();