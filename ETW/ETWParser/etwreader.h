#pragma once

#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

#include "globals.h"

bool start_etw_reader(std::vector<HANDLE>& threads);
void stop_etw_reader();
std::vector<json> get_events();

static const std::string TYPE = "type";
static const std::string TIMESTAMP = "timestamp";
static const std::string PID = "PID";
//static const std::string TID = "TID";
static const std::string TASK = "task";
static const std::string EVENT_ID = "event_id";
static const std::string PROVIDER_NAME = "provider_name";

static const std::string attack_exe_path = "C:\\Users\\hacker\\source\\repos\\EDR-Introspection\\x64\\Release\\Injector.exe";
static const std::string injected_exe_path = "C:\\Program Files\\WindowsApps\\Microsoft.WindowsNotepad_11.2506.35.0_x64__8wekyb3d8bbwe\\Notepad\\Notepad.exe";

static const std::string attack_exe_name = attack_exe_path.substr(attack_exe_path.find_last_of("\\") + 1);
static const std::string injected_exe_name = injected_exe_path.substr(injected_exe_path.find_last_of("\\") + 1);

// keys that get merged together
struct MergeCategory {
    std::string merged_key;
    std::vector<std::string> keys_to_merge;
};

// keys to merge for PPID and FilePath
MergeCategory ppid_keys = {
    "PPID",
    {"Parent PID", "TPID"} // Target PID, TargetPID?
};
MergeCategory filepath_keys = {
    "FilePath",
    {"Base Path", "FileName", "File Name", "filepath", "File Path", "Image Path", "Image Name", "Path", "Process Image Path", "Name", "Reason Image Path"}
};
std::vector<MergeCategory> key_categories_to_merge = { ppid_keys, filepath_keys };