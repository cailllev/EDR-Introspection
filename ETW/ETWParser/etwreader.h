#pragma once

#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

#include "globals.h"

bool start_etw_traces(std::vector<HANDLE>& threads);
void stop_etw_traces();
std::vector<json> get_events();
std::vector<json> get_events_unfiltered();
void print_etw_counts();

static const std::string TYPE = "type";
static const std::string TIMESTAMP = "timestamp";
static const std::string PID = "PID";
static const std::string TID = "TID";
static const std::string EXE = "Exe";
static const std::string TASK = "task";
static const std::string EVENT_ID = "event_id";
static const std::string PROVIDER_NAME = "provider_name";

static const std::string injected_exe_path = "C:\\Program Files\\WindowsApps\\Microsoft.WindowsNotepad_11.2506.35.0_x64__8wekyb3d8bbwe\\Notepad\\Notepad.exe";
static const std::string shellcode_exe_path = "C:\\Program Files\\WindowsApps\\Microsoft.WindowsCalculator_11.2502.2.0_x64__8wekyb3d8bbwe\\CalculatorApp.exe";

static const std::string attack_exe_name = attack_exe_path.substr(attack_exe_path.find_last_of("\\") + 1);
static const std::string injected_exe_name = injected_exe_path.substr(injected_exe_path.find_last_of("\\") + 1);
static const std::string shellcode_exe_name = shellcode_exe_path.substr(shellcode_exe_path.find_last_of("\\") + 1);

static const std::vector<std::string> exe_paths_to_track = { attack_exe_path, injected_exe_path, shellcode_exe_path };

// keys that get merged together
struct MergeCategory {
    std::string merged_key;
    std::vector<std::string> keys_to_merge;
};

// keys to merge for PPID and FilePath
extern MergeCategory ppid_keys;
extern MergeCategory tpid_keys;
extern MergeCategory filepath_keys;
extern std::vector<MergeCategory> key_categories_to_merge;
