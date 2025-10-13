#pragma once

#include "etwparser.h"
#include "profile.h"

#include <vector>
#include <string>


// defaults
static const std::string all_events_output_default = "C:\\Users\\Public\\Downloads\\all-events.csv";

// executables to track for kernel event filtering, i.e. their PIDs at runtime
static const std::vector<std::string> exes_to_track = {
    // attack_PID and injected_PID are added to g_tracking_PIDs at runtime, not as exes here (they are not running at startup)
    "smartscreen.exe", "System"
};
