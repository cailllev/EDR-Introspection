#include "pch.h"
#include <windows.h>
#include <fstream>

void write_file(std::string msg) {
    std::ofstream outfile("C:\\Users\\Public\\Downloads\\SimpleDLL-out.txt");
    if (outfile.is_open())
    {
        outfile << msg;
        outfile.close();
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  reasonForCall, LPVOID lpReserved) {
    switch (reasonForCall)
    {
    case DLL_PROCESS_ATTACH:
        write_file("dll loaded");
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
