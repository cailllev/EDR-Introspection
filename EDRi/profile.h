#pragma once

#include <string>
#include <functional>

#include "globals.h"


class EdrProfile {
public:
    std::string edr_exe_name;
    bool started;
    bool ended;

    std::function<void(const json&)> check_start;
    std::function<void(const json&)> check_end;

    EdrProfile(std::string exe,
               std::function<bool(const json&, EdrProfile&)> start_filter,
               std::function<bool(const json&, EdrProfile&)> end_filter)
        : edr_exe_name(exe), started(false), ended(false)
    {
        check_start = [this, start_filter](const json& event) {
            if (!this->started && start_filter(event, *this)) {
                this->started = true;
                std::cout << "[+] Profile: Detected first ETW event\n";
            }
        };

        check_end = [this, end_filter](const json& event) {
            if (!this->ended && end_filter(event, *this)) {
                this->ended = true;
                std::cout << "[+] Profile: Detected termination of attack PID\n";
            }
        };
    }
};

std::string get_edr_profiles();
void set_edr_profile(std::string);
void edr_profile_check_start(json& ev);
void edr_profile_check_end(json& ev);
bool edr_profile_is_trace_running();
bool edr_profile_is_trace_stopped();