#pragma once

#include <vector>

struct ProcessStartFilter {
	std::string provider;
	int event_id;
};

// Antimalware Trace
static const std::vector<int> am_event_ids_to_remove = { 7, 44, 62 }; // TODO also remove 11, 111, 112? (noisy)
static const std::vector<int> am_event_ids_with_pid = { 5, 6, 11, 15, 16, 26, 29, 104, 105, 109, 110, 111, 112, 60, 70, 71, 72, 73 };
static const std::vector<int> am_event_ids_with_pid_and_tpid = { 53 };
static const std::vector<int> am_event_ids_with_pid_in_data = { 43, 67 };
static const std::vector<int> am_event_ids_with_message = { 3 };
static const std::vector<int> am_event_ids_with_filepath = { 30, 31, 35, 36, 37, 38 };
static const std::vector<int> am_event_ids_with_signatures = { 59 }; // TODO find a way to filter event 59


// TODO many kernel events, create new (vebose) filter layout? --> minimal events, verbose events (kernel + antimalware 11), all events
// TODO all kernel events should be filtered, are event ids still needed?
// Kernel Process Trace
static const std::vector<int> kproc_event_ids_with_tpid = { 1, 2, 3, 4, 5, 6, 11 }; // todo thread start stop & image load unload (3456) also relevant for ALL security pids?
// Kernel API Calls Trace
static const std::vector<int> kapi_event_ids_with_tpid = { 2, 5, 6 };
static const std::vector<int> kapi_event_ids_with_pid = { 3 };
// Kernel File Trace
static const std::vector<int> kfile_event_ids_with_pid = { 10, 30 };
// Kernel Network Trace
static const std::vector<int> knetwork_event_ids_with_pid_or_opid = { 12, 15, 28, 31, 42, 43, 58, 59 };