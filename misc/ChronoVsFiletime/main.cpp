#include <chrono>
#include <iostream>
#include <Windows.h>

int main() {
    using namespace std::chrono;
    constexpr std::size_t N = 1'000'000'000;

    FILETIME ft;
    volatile ULARGE_INTEGER uli;
	auto chrono_now = system_clock::now(); // needs to be declared else compile error in lambda function benchmark
    volatile UINT64 sink = 0;

    std::cout << "[*] Timing " << N << " calls each...\n";

    auto benchmark = [&](auto func, const char* name) {
        auto start = steady_clock::now();
        for (std::size_t i = 0; i < N; ++i)
            func();
        auto end = steady_clock::now();

        auto ms = duration<double, std::milli>(end - start).count();
        double ns_per_call = (ms * 1'000'000.0) / N;
        std::cout << ns_per_call << " ns per call - " << name << "\n";
        };

    benchmark([&] { // GetSystemTimeAsFileTime
        ::GetSystemTimeAsFileTime(&ft);
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        sink = uli.QuadPart * 100;
        }, "GetSystemTimeAsFileTime");

	benchmark([&] { // GetSystemTimePreciseAsFileTime
        ::GetSystemTimePreciseAsFileTime(&ft);
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        sink = uli.QuadPart * 100;
        }, "GetSystemTimePreciseAsFileTime");

	benchmark([&] { // chrono::system_clock::now()
        chrono_now = system_clock::now();
        sink = duration_cast<nanoseconds>(chrono_now.time_since_epoch()).count();
        }, "chrono::system_clock::now()");
}