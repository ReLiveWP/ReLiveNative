#include "globals.h"
#include "logging.h"
#include "wlidcomm.h"

using namespace msidcrl::globals;


extern "C"
{
LONG WINAPI MSIDCRL_ExceptionHandler(EXCEPTION_POINTERS *pExceptionInfo);

    BOOL DllMain(
        HINSTANCE hinstDLL, // handle to DLL module
        DWORD fdwReason,    // reason for calling function
        LPVOID lpvReserved) // reserved
    {
        // Perform actions based on the reason for calling.
        switch (fdwReason)
        {
        case DLL_PROCESS_ATTACH:
            InitializeCriticalSection(&g_hDriverCrtiSec);
            break;

        case DLL_THREAD_ATTACH:
            // Do thread-specific initialization.
            break;

        case DLL_THREAD_DETACH:
            // Do thread-specific cleanup.
            break;

        case DLL_PROCESS_DETACH:

            if (lpvReserved != nullptr)
            {
                break; // do not do cleanup if process termination scenario
            }

            // Perform any necessary cleanup.
            break;
        }
        return TRUE; // Successful DLL_PROCESS_ATTACH.
    }
}