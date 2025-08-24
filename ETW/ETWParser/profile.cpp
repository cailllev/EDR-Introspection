# include "profile.h"

EDR defender = {
	"Defender",
	0, // TODO: startup parameter
	false, // started
	[](const krabs::schema& schema) -> bool {
		// start filter
		if (/*!started && */std::wstring(schema.provider_name()) == std::wstring(L"Microsoft-Antimalware-Engine") &&
			schema.event_id() == 4 && std::wstring(schema.task_name()) == std::wstring(L"Versions ")) {
			//started = true;
			return true;
		}
		return false;
	},
	false, // ended
	[](const krabs::schema& schema) -> bool {
		// end filter
		if (/*!ended && */std::wstring(schema.provider_name()) == std::wstring(L"Microsoft-Antimalware-Engine") &&
			schema.event_id() == 73 && std::wstring(schema.task_name()) == std::wstring(L"Versions ")) {
			//ended = true;
			return true;
		}
		return false;
	}
};