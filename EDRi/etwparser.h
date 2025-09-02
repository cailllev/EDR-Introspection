#pragma once

#include <krabs.hpp>
#include <vector>
#include <string>

#include "globals.h"


struct Event {
    const EVENT_RECORD& record;
    const krabs::schema schema;
};

std::vector<json> get_events();
std::vector<json> get_events_unfiltered();
void print_etw_counts();

void my_event_callback(const EVENT_RECORD&, const krabs::trace_context&);
void event_callback(const EVENT_RECORD&, const krabs::trace_context&);
json parse_my_etw_event(Event);
json parse_etw_event(Event);
void count_event(json, bool);
void post_parsing_checks(json&);
bool filter(json&);
bool filter_antimalware_etw(json&);
bool filter_kernel_api_calls(json&);


static const std::string TIMESTAMP = "timestamp";
static const std::string TYPE = "type";
static const std::string PROVIDER_NAME = "providername";
static const std::string EVENT_ID = "eventid";
static const std::string TASK = "task";
static const std::string PID = "pid";
static const std::string TID = "tid";
static const std::string EXE = "exe";
static const std::string TARGET_PID = "targetpid";
static const std::string FILEPATH = "filepath";
static const std::string MESSAGE = "message";
static const std::string DATA = "data";

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