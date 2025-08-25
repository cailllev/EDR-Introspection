#pragma once

#include <vector>
#include <string>
#include "etwreader.h"


// defaults
std::string all_events_output_default = "C:\\Users\\Public\\Downloads\\all-events.csv";

// keys to merge for PPID and FilePath
static const std::vector<std::string> ppid_keys = {
    "PPID",  "Parent PID", "TPID", "Target PID", "TargetPID" // TargetPID?
};
std::string ppid_merged_key = "PPID";
static const std::vector<std::string> filepath_keys = {
    "FileName", "File Name", "File Path", "Image Path", "Process Image Path", "Name", "Reason Image Path" // FileName, ImageName?
};
std::string filepath_merged_key = "FilePath";
std::vector<std::vector<std::string>> key_categories_to_merge = { ppid_keys, filepath_keys };


// define start of CSV header, all other keys are added in order later
std::vector<std::string> csv_header_start = { TIMESTAMP, TYPE, PROVIDER_NAME, EVENT_ID, TASK, PID, TID,
    ppid_merged_key, "Message", "Command Line", filepath_merged_key, "VName", "Sig Seq", "Sig Sha" };