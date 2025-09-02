#include <iostream>

#include "profile.h"
#include "etwparser.h"

static const std::map<std::string, std::shared_ptr<EdrProfile>> edr_profiles = {
    {"Defender", std::make_shared<EdrProfile>(
        "MsMpEng.exe",
        [](const json& ev, EdrProfile& self) {
            return (ev[PROVIDER_NAME] == ANTIMALWARE_PROVIDER &&
                    ev[EVENT_ID] == ANTIMALWARE_ATTACH_EVENT_ID &&
                    ev[TASK] == ATTACH_EVENT_TASK);
        },
        [](const json& ev, EdrProfile& self) {
            return (ev[PROVIDER_NAME] == ANTIMALWARE_PROVIDER &&
                    ev[PID] == g_attack_PID &&
                    ev[EVENT_ID] == PROCESS_START_STOP_EVENT_ID &&
                    ev[SOURCE] == TERMINATION);
        }
    )}
};

static std::shared_ptr<EdrProfile> edrp = nullptr;
static bool already_set;

std::string get_edr_profiles() {
    std::string s = "";
    for (auto it = edr_profiles.begin(); it != edr_profiles.end(); ++it) {
        s += it->first + ",";
    }
    return s.substr(0, s.length() - 1); // remove last ","
}

void set_edr_profile(const std::string name) {
    if (already_set) {
        std::cout << "[-] Profile: Already set EDR profile, cannot change it now\n";
    }
    auto it = edr_profiles.find(name);
    if (it == edr_profiles.end()) {
        std::cerr << "[!] Profile: Unsupported EDR profile: " << name << "\n";
        exit(1);
    }
    edrp = it->second;
    std::cout << "[+] Profile: Set EDR to " << name << "\n";
}

// mhh yes, pointers
void edr_profile_check_start(json& ev) {
    if (edrp) {
        edrp->check_start(ev);
    }
}

void edr_profile_check_end(json& ev) {
    if (edrp) {
        edrp->check_end(ev);
    }
}

bool edr_profile_is_trace_running() {
    return edrp && edrp->started;
}

bool edr_profile_is_trace_stopped() {
    return edrp && edrp->ended;
}
