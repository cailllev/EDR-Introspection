#pragma once

#include <vector>
#include <string>
#include "etwreader.h"


// defaults
std::string all_events_output_default = "C:\\Users\\Public\\Downloads\\all-events.csv";


// define start of CSV header, all other keys are added in order later
std::vector<std::string> csv_header_start = { 
    TIMESTAMP, TYPE, PROVIDER_NAME, EVENT_ID, TASK, PID, ppid_keys.merged_key, 
    "TargetPID", "Message", filepath_keys.merged_key, "Command Line", "First Param", "Second Param",
    "Cache Name", "Result", "VName", "Sig Seq", "Sig Sha"
};
