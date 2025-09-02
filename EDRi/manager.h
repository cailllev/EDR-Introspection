#pragma once

#include "etwparser.h"
#include "profile.h"

#include <vector>
#include <string>


// defaults
static const std::string all_events_output_default = "C:\\Users\\Public\\Downloads\\all-events.csv";

// define start of CSV header, all other keys are added in order later
std::vector<std::string> csv_header_start = { 
    TIMESTAMP, TYPE, PROVIDER_NAME, EVENT_ID, TASK, PID, TID, EXE, ppid_keys.merged_key, tpid_keys.merged_key, "message",
    filepath_keys.merged_key, "cachename", "result", "vname", "sigseq", "sigsha", "commandline", "firstparam", "secondparam",
};
