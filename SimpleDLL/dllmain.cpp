#include "pch.h"
#include <windows.h>
#include <fstream>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        std::ofstream outfile("C:\\Users\\Public\\Downloads\\SimpleDLL-out.txt");
        if (outfile.is_open())
        {
            outfile << "ok";
            outfile.close();
        }
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
