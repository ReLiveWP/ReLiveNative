#include "globals.h"
#include "logging.h"
#include "wlidcomm.h"

using namespace msidcrl::globals;

extern "C"
{
    LONG WINAPI MSIDCRL_ExceptionHandler(struct _EXCEPTION_POINTERS *pExceptionInfo)
    {
        LOG_MESSAGE_FMT(L"Is this thing on?? ExceptionHandler called in client DLL!!! ExceptionCode=0x%08x; ExceptionAddress=0x%08x; ExceptionInformation0x%08x;",
                        pExceptionInfo->ExceptionRecord->ExceptionCode,
                        pExceptionInfo->ExceptionRecord->ExceptionAddress,
                        pExceptionInfo->ExceptionRecord->ExceptionInformation);

#if defined(UNDER_CE) && defined(ARM)

        

#endif

        return EXCEPTION_CONTINUE_SEARCH;
    }

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
            AddVectoredExceptionHandler(1, MSIDCRL_ExceptionHandler);
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