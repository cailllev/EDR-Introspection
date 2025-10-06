#include <map>
#include <vector>

#include "profile.h"

// the first exe is the main edr exe
static const std::map<std::string, std::vector<std::string>> edr_profiles = {
	{ "Defender", {"MsMpEng.exe", "MpDefenderCoreService.exe"} },
    { "MDE", {"MsMpEng.exe", "MpDefenderCoreService.exe", "MsSense.exe", "SenseCnCProxy.exe", "SenseIR.exe", "SenseCE.exe", "SenseSampleUploader.exe", "SenseNdr.exe", "SenseSC.exe", "SenseCM.exe", "SenseTVM.exe"} },
    { "Cortex", {"cyserver.exe", "cysandbox.exe", "cywscsvc.exe", "tlaworker.exe", "cortex-xdr-payload.exe", "cyuserserver.exe"}} // TODO multiple procs, multiple main exes
};

std::string get_available_edrs() {
	std::string available_edrs = "";
    for (auto it = edr_profiles.begin(); it != edr_profiles.end(); ++it) {
        available_edrs += it->first;
        if (std::next(it) != edr_profiles.end())
            available_edrs += ", ";
    }
    return available_edrs;
}
