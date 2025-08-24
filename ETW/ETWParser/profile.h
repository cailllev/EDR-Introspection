#pragma once
#include <string>
#include <krabs.hpp>

struct EDR {
	std::string name;
	int PID_to_track;
	bool started = false;
	bool (*filter_start)(const krabs::schema& schema);
	bool ended = false;
	bool (*filter_end)(const krabs::schema& schema);
};