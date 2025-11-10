#include <map>
#include <vector>

#include "profile.h"

EDR_Profile defender = { { "MsMpEng.exe" }, { "MpDefenderCoreService.exe" } };
EDR_Profile mde = { { "MsMpEng.exe" }, { "MpDefenderCoreService.exe", "MsSense.exe", "SenseCnCProxy.exe", "SenseIR.exe", "SenseCE.exe", "SenseSampleUploader.exe", "SenseNdr.exe", "SenseSC.exe", "SenseCM.exe", "SenseTVM.exe" } };
EDR_Profile cortex = { { "cyserver.exe", "cysandbox.exe" } , { "cywscsvc.exe", "tlaworker.exe", "cortex-xdr-payload.exe", "cyuserserver.exe", "cyrprtui.exe", "cydump.exe", "CyveraConsole.exe" } };

static const std::map<std::string, EDR_Profile> edr_profiles = {
    { "Defender", defender },
    { "MDE", mde },
    { "Cortex",  cortex }
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

std::vector<std::string> get_all_edr_exes(const EDR_Profile& exes) {
    std::vector<std::string> all = exes.main_exes;
    all.insert(all.end(), exes.other_exes.begin(), exes.other_exes.end());
    return all;
}