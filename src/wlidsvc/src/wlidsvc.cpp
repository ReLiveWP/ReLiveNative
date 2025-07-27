
#include <windows.h>
#include "log.h"
#include "wlidcomm.h"
#include "util.h"
#include "ioctls.h"

using namespace wlidsvc;

extern "C"
{
	static int g_instanceCount = 0;
	static HANDLE g_hWlidSvcReady = NULL;
	static CRITICAL_SECTION g_wlidSvcReadyCritSect = {0};

	BOOL DllMain(
		HINSTANCE hinstDLL, // handle to DLL module
		DWORD fdwReason,	// reason for calling function
		LPVOID lpvReserved) // reserved
	{
		// Perform actions based on the reason for calling.
		switch (fdwReason)
		{
		case DLL_PROCESS_ATTACH:
			InitializeCriticalSection(&g_wlidSvcReadyCritSect);
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

	DWORD WLI_Init(DWORD hContext)
	{
		log::info().log(L"WLI_Init called!");

		{
			util::critsect_t cs{&g_wlidSvcReadyCritSect};
			if (g_hWlidSvcReady == NULL)
			{
				g_hWlidSvcReady = CreateEvent(NULL, TRUE, FALSE, WLIDSVC_READY_EVENT);
			}
		}

		EventModify(g_hWlidSvcReady, EVENT_SET);

		return 0x8000000 + (++g_instanceCount);
	}

	BOOL WLI_Deinit(DWORD hContext)
	{
		return FALSE;
	}

	DWORD WLI_Open(DWORD hContext, DWORD dwAccess, DWORD dwShareMode)
	{
		return (DWORD)TRUE;
	}

	BOOL WLI_Close(DWORD hContext)
	{
		return TRUE;
	}

	DWORD WLI_Write(DWORD hContext, LPCVOID pInBuf, DWORD dwInLen)
	{
		return (DWORD)-1;
	}

	DWORD WLI_Read(DWORD hContext, LPVOID pBuf, DWORD dwLen)
	{
		return (DWORD)-1;
	}

	BOOL WLI_IOControl(DWORD hContext, DWORD dwCode, PBYTE pBufIn,
					   DWORD dwLenIn, PBYTE pBufOut, DWORD dwLenOut,
					   PDWORD pdwActualOut)
	{
		BEGIN_IOCTL_MAP()
		IOCTL_HANDLER(IOCTL_WLIDSVC_LOG_MESSAGE, WLI_HandleLogMessage)
		IOCTL_HANDLER(IOCTL_WLIDSVC_LOG_MESSAGE_WIDE, WLI_HandleLogMessageWide)
		END_IOCTL_MAP()
		return FALSE;
	}

	DWORD WLI_Seek(DWORD hContext, long pos, DWORD type)
	{
		return (DWORD)-1;
	}

	void WLI_PowerUp(void)
	{
		return;
	}

	void WLI_PowerDown(void)
	{
		return;
	}
}