#include <iostream>
#include <map>

#include "helpers/json.hpp"
#include "filter.h"
#include "etwparser.h"


std::map<Classifier, std::string> classifier_names = {
    { All, "All" },
    { Relevant, "Relevant" },
    { Minimal, "Minimal" }
};

// calculate once before doing all the filtering
static std::vector<ProcInfo> tracked_procs = {};

// adds exe name to all pid fields, only use AFTER filtering!
void add_exe_information(json& j, Classifier c) {
	for (auto it = j.begin(); it != j.end(); ++it) { // iterate over all fields
        const std::string& key = it.key();
        json& value = it.value();

        if (j.contains(TIMESTAMP_NS)) {
            UINT64 timestamp_ns = j[TIMESTAMP_NS];

            // add info for all pid fields
            if (std::find(fields_to_add_exe_name.begin(), fields_to_add_exe_name.end(), key) != fields_to_add_exe_name.end()) {
                std::string exe_name = get_proc_name(value, timestamp_ns, RESERVE_NS);

                if (exe_name == PROC_NOT_FOUND && c == Minimal && g_debug) { // warn when important event cannot add it's PID name
                    try {
                        std::cout << "[!] Utils: No process found with " << key << "=" << value << " at " << unix_epoch_ns_to_iso8601(timestamp_ns) << " : ";
                        std::cout << "provider=" << j[PROVIDER_NAME] << ",eventId=" << j[EVENT_ID] << ",task=" << j[TASK] << "\n";
                    }
                    catch (...) {}
                }

                std::ostringstream oss;
                oss << std::setw(5) << value.get<int>(); // pad pid up to 5 digits, allows for "alphabetical sort" == "numerical sort"
                value = oss.str() + " " + exe_name; // add exe name "in place" (reference)
            }
        }
        else if (g_debug) {
            std::cout << "[!] Filter: Empty " << TIMESTAMP_NS << " field in event, cannot add exe information: " << j.dump() << "\n";
        }

    }
}

// filter all events
std::map<Classifier, std::vector<json>> filter_all_events(std::vector<json> events) {
	std::cout << "[+] Filter: Filtering " << events.size() << " events into All, Relevant and Minimal\n";
    std::map<Classifier, std::vector<json>> etw_events = {
        { All, {} },
        { Relevant, {} },
        { Minimal, {} }
    };

    tracked_procs = get_tracked_procs();
    int skipped = 0;
    for (auto& ev : events) {
        if (ev.is_null() || !ev.contains(TIMESTAMP_SYS) || !ev[TIMESTAMP_SYS].is_string()) {
            skipped++;
			continue;
        }
        try {
            Classifier c = filter(ev);
            add_exe_information(ev, c); // now add exe info to all pid fields
            c = filter_post_exe(ev, c);

            switch (c) {
            case Minimal:
                etw_events[Minimal].push_back(ev);
                // do not break, also add to relevant and all
            case Relevant:
                etw_events[Relevant].push_back(ev);
                // do not break, also add to all
            case All:
                etw_events[All].push_back(ev);
                break;
            }
        }
        catch (...) {
            std::cout << "[!] Filter: filter_all_events exception on event: " << ev.dump() << "\n";
        }
	}
    if (g_debug) {
        std::cout << "[-] Filter: Skipped " << skipped << " events due to missing " << TIMESTAMP_SYS << " field\n";
    }

    return etw_events;
}

// filter based on provider
Classifier filter(json& ev) {
    if (ev[PROVIDER_NAME] == KERNEL_PROCESS_PROVIDER) {
        return filter_kernel_process(ev);
    }

    else if (ev[PROVIDER_NAME] == THREAT_INTEL_PROVIDER) {
        return filter_threat_intel(ev);
    }

    else if (ev[PROVIDER_NAME] == KERNEL_API_PROVIDER) {
        return filter_kernel_api_call(ev);
    }

    else if (ev[PROVIDER_NAME] == KERNEL_FILE_PROVIDER) {
        return filter_kernel_file(ev);
    }

    else if (ev[PROVIDER_NAME] == KERNEL_NETWORK_PROVIDER) {
        return filter_kernel_network(ev);
    }

    else if (ev[PROVIDER_NAME] == ANTIMALWARE_PROVIDER) {
        return filter_antimalware(ev);
    }

    // MY PROVIDERS
    else if (ev[PROVIDER_NAME] == HOOK_PROVIDER) {
        return filter_hooks(ev);
    }
    else if (ev[PROVIDER_NAME] == EDRi_PROVIDER) {
        return Minimal; // do not filter
    }
    else if (ev[PROVIDER_NAME] == ATTACK_PROVIDER) {
        return Minimal; // do not filter
    }

    if (g_super_debug) {
        std::cout << "[+] Filter: Unfiltered provider " << ev[PROVIDER_NAME] << ", not filtering its event ID " << ev[EVENT_ID] << "\n";
    }

    return Relevant; // do not filter unregistered providers
}

bool is_exe_in_field(json& ev, std::string field, std::string exe_name) {
    if (!ev.contains(field)) {
        return false;
    }
    std::string val = ev[field];
    return val.find(exe_name) != std::string::npos; // field may now have PID+EXE, must check if contains, not ==
}


// filter out known irrelevant exes
Classifier filter_post_exe(json& ev, Classifier previous_c) {
    if (ev[PROVIDER_NAME] == KERNEL_API_PROVIDER) {
        for (auto& i : kapi_irrelevant_exe) {
            std::string exe = i.first;
            std::string field = i.second;
            if (is_exe_in_field(ev, exe, field)) {
                return All;
            }

        }
    }
    return previous_c; // for now only KERNEL_API is filtered post add_exe_information
}

// returns a classifier based on if the value is in list
Classifier classify_to(json& ev, std::string key, std::vector<ProcInfo> procs) {
    if (ev.contains(key)) {
        for (auto& p : procs) {
            if (p.PID == ev[key]) { // check if a proc in procs match the searched PID
                if (ev[TIMESTAMP_NS] >= p.start_time && ev[TIMESTAMP_NS] <= p.end_time) { // check if it was running at this time
                    return Minimal; // found -> put in Minimal
                }
            }
        }
        return All; // when value not found --> put in All
    }
    else if (g_debug) {
        std::cout << "[-] Filter: Warning: Event with ID " << ev[EVENT_ID] << " missing " << key << " field to filter: " << ev.dump() << "\n";
    }
    return Relevant; // expected key does not exists, classify as relevant (for now)
}

// filter kernel process events
Classifier filter_kernel_process(json& ev) {
    if (std::find(kproc_event_ids_with_pid_or_tpid_minimal.begin(), kproc_event_ids_with_pid_or_tpid_minimal.end(), ev[EVENT_ID]) != kproc_event_ids_with_pid_or_tpid_minimal.end()) {
        // only include events if pid is attack or injected OR a tracked_process is the target of a process operation
        Classifier c_pid = classify_to(ev, PID, { g_attack_proc, g_injected_proc });
        Classifier c_tpid = classify_to(ev, TARGET_PID, tracked_procs);
        if (c_pid == Minimal || c_tpid == Minimal) {
            return Minimal; // put in minimal if either matches
        } // else put it in relevant
        return Relevant;
    }
    // thread start and stop are only interesting with attack pid / tpid
    if (std::find(kproc_event_ids_with_attack_pid_tpid.begin(), kproc_event_ids_with_attack_pid_tpid.end(), ev[EVENT_ID]) != kproc_event_ids_with_attack_pid_tpid.end()) {
        Classifier c_pid = classify_to(ev, PID, { g_attack_proc });
        Classifier c_tpid = classify_to(ev, TARGET_PID, { g_attack_proc });
        if (c_pid == Minimal || c_tpid == Minimal) {
            return Minimal; // put in minimal if either matches
        } // else put it in relevant
        return Relevant;
    }
    // image load and unload events are at most relevant, not minimal (very noisy)
    if (std::find(kproc_event_ids_with_tpid_relevant.begin(), kproc_event_ids_with_tpid_relevant.end(), ev[EVENT_ID]) != kproc_event_ids_with_tpid_relevant.end()) {
        Classifier c = classify_to(ev, TARGET_PID, tracked_procs);
        if (c == Minimal) {
            return Relevant; // put in relevant if matches
        }
        return c; // else put it in relevant or all accordingly
    }
    return Relevant; // put event ids without a filter into relevant
}

// filter kernel api calls
Classifier filter_kernel_api_call(json& ev) {
    // the interesting info is in target pid, process_id of msmpeng.exe/attack.exe/smartscreen.exe etc is not enough to filter
    if (std::find(kapi_event_ids_with_tpid.begin(), kapi_event_ids_with_tpid.end(), ev[EVENT_ID]) != kapi_event_ids_with_tpid.end()) {
        // only relevant if interacted with the attack / injected
        // X syscall -> Defender/System/smartscreen => irrelevant
        return classify_to(ev, TARGET_PID, { g_attack_proc, g_injected_proc });
    }
    if (std::find(kapi_event_ids_with_pid.begin(), kapi_event_ids_with_pid.end(), ev[EVENT_ID]) != kapi_event_ids_with_pid.end()) {
        return classify_to(ev, PID, tracked_procs);
    }
    return Relevant; // put event ids without a filter into relevant
}

// filter kernel file events
Classifier filter_kernel_file(json& ev) {
    if (std::find(kfile_event_ids_with_pid.begin(), kfile_event_ids_with_pid.end(), ev[EVENT_ID]) != kfile_event_ids_with_pid.end()) {
        return classify_to(ev, PID, tracked_procs);
    }
    return Relevant; // put event ids without a filter into relevant
}

// filter kernel network events
Classifier filter_kernel_network(json& ev) {
    // events to keep if PID or originating PID match
    if (std::find(knet_event_ids_with_pid_or_opid.begin(), knet_event_ids_with_pid_or_opid.end(), ev[EVENT_ID]) != knet_event_ids_with_pid_or_opid.end()) {
        Classifier c_pid = classify_to(ev, PID, tracked_procs);
        Classifier c_orig = classify_to(ev, ORIGINATING_PID, tracked_procs);
        if (c_pid == Minimal || c_orig == Minimal) {
            return Minimal; // put in minimal if either matches
        } // else put it in relevant
    }
    return Relevant; // put event ids without a filter into relevant
}

// filter threat intel events
Classifier filter_threat_intel(json& ev) {
    // either pid or tpid must match a tracked pid
    if (std::find(ti_events_with_pid_or_tpid.begin(), ti_events_with_pid_or_tpid.end(), ev[EVENT_ID]) != ti_events_with_pid_or_tpid.end()) {
        Classifier c_pid = classify_to(ev, PID, tracked_procs);
        Classifier c_orig = classify_to(ev, TARGET_PID, tracked_procs);
        if (c_pid == Minimal || c_orig == Minimal) {
            return Minimal; // put in minimal if either matches
        } // else put it in relevant
    }
    return Relevant; // put event ids without a filter into relevant
}

// filter events based on known exclude values (e.g. wrong PID for given event id)
Classifier filter_antimalware(json& ev) {
    // events to remove
    if (std::find(am_event_ids_to_remove.begin(), am_event_ids_to_remove.end(), ev[EVENT_ID]) != am_event_ids_to_remove.end()) {
        return All;
    }

    // events to keep if originating PID matches attack or injected PID
    if (std::find(am_event_ids_with_opid.begin(), am_event_ids_with_opid.end(), ev[EVENT_ID]) != am_event_ids_with_opid.end()) {
        Classifier c = classify_to(ev, ORIGINATING_PID, { g_attack_proc, g_injected_proc });
        if (c == All) {
            return All; // put in all if it does not match
        }
        if (std::find(am_event_ids_with_pid_but_noisy.begin(), am_event_ids_with_pid_but_noisy.end(), ev[EVENT_ID]) != am_event_ids_with_pid_but_noisy.end()) {
            return Relevant; // put noisy events into relevant (can overwrite minimal from above)
        }
        return c; // else return as classified originally
    }

    // events to keep if originating PID or TargetPID matches attack PID or injected PID
    if (std::find(am_event_ids_with_opid_and_tpid.begin(), am_event_ids_with_opid_and_tpid.end(), ev[EVENT_ID]) != am_event_ids_with_opid_and_tpid.end()) {
        Classifier c_orig = classify_to(ev, ORIGINATING_PID, { g_attack_proc, g_injected_proc });
        Classifier c_target = classify_to(ev, TARGET_PID, { g_attack_proc, g_injected_proc });
        if (c_orig == Minimal || c_target == Minimal) {
            return Minimal; // put in minimal if either matches
        } // else put it in relevant
        return Relevant;
    }

    // events to keep if PID in Data matches
    if (std::find(am_event_ids_with_pid_in_data.begin(), am_event_ids_with_pid_in_data.end(), ev[EVENT_ID]) != am_event_ids_with_pid_in_data.end()) {
        return classify_to(ev, DATA, { g_attack_proc, g_injected_proc });
    }

    // events to keep if Message contains filter string (case insensitive)
    if (std::find(am_event_ids_with_message.begin(), am_event_ids_with_message.end(), ev[EVENT_ID]) != am_event_ids_with_message.end()) {
        if (ev.contains(MESSAGE)) {
            std::string msg = ev[MESSAGE];
            std::transform(msg.begin(), msg.end(), msg.begin(), [](unsigned char c) { return std::tolower(c); });
            if (msg.find(g_attack_exe_name) != std::string::npos ||
                msg.find(injected_exe) != std::string::npos ||
                msg.find(invoked_name) != std::string::npos) {
                return Minimal; // do not filter if any of the strings match
            }
            return All; // else filter out
        }
        else if (g_debug) {
            std::cout << "[-] Filter: Warning: Event with ID " << ev[EVENT_ID] << " missing " << MESSAGE << " field: " << ev.dump() << "\n";
        }
        return Relevant; // unexpected event fields, do not filter
    }

    // events to keep if it's related to attack exe
    // 30,31 = CreateNewFile,UfsScanFileTask
    // 35-38 = Cache operations
    if (std::find(am_event_ids_with_filepath.begin(), am_event_ids_with_filepath.end(), ev[EVENT_ID]) != am_event_ids_with_filepath.end()) {
        if (ev.contains(FILEPATH)) {
            std::string path = ev[FILEPATH];
            if (path.find(g_attack_exe_name) != std::string::npos) {
                return Minimal; // do not filter if path matches
            }
            return All; // else filter out
        }
        else if (g_debug) {
            std::cout << "[-] Filter: Warning: Event with ID " << ev[EVENT_ID] << " missing " << FILEPATH << " field: " << ev.dump() << "\n";
        }
        return Relevant; // unexpected event fields, do not filter
    }

    // events to keep if pipe matches (via PID)
    if (std::find(am_event_ids_with_pipe.begin(), am_event_ids_with_pipe.end(), ev[EVENT_ID]) != am_event_ids_with_pipe.end()) {
        if (ev.contains(FILEPATH)) {
            std::string pipe_info = ev[FILEPATH]; // \\.\proc\Process:12888,134064706853298289
            if (pipe_info.find(std::to_string(g_attack_proc.PID)) != std::string::npos || pipe_info.find(std::to_string(g_injected_proc.PID)) != std::string::npos) {
                return Minimal;
            }
            return All;
        }
        else if (g_debug) {
            std::cout << "[-] Filter: Warning: Event with ID " << ev[EVENT_ID] << " missing " << FILEPATH << " field: " << ev.dump() << "\n";
        }
        return Relevant; // unexpected event fields, do not filter
    }

    return Relevant; // put event ids without a filter into relevant
}

// filter hook provider for relevant processes, either attack or injected PID -> Minimal, else All
Classifier filter_hooks(json& ev) {
    const std::string& msg = ev[MESSAGE];

	// when msg starts with NtOpenFile, NtReadFile, NtCreateFile, ..., there is no usable targetpid --> check for attack / injected exe name
    // example: NtOpenFile \??\C:\WINDOWS\SYSTEM32\whoami.exe with 0x100021
    if (msg.find("NtOpenFile", 0) == 0 || msg.find("NtReadFile", 0) == 0 || msg.find("NtCreateFile", 0) == 0) {
        if (msg.find(g_attack_exe_name) != std::string::npos || msg.find(injected_exe) != std::string::npos) {
            return Minimal;
        }
        else {
            return All; // openfile to other than attack / injected --> irrelevant
        }
    }
    // else event has a usable targetpid --> classify based on target pid
    return classify_to(ev, TARGET_PID, { g_attack_proc, g_injected_proc });
}
