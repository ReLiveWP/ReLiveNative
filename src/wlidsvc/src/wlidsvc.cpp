
#include <windows.h>
#include "log.h"
#include "wlidcomm.h"
#include "util.h"
#include "ioctls.h"
#include "globals.h"

using namespace wlidsvc;
using namespace wlidsvc::globals;

extern "C"
{
	DWORD_PTR WLI_Init(DWORD_PTR hContext)
	{
		LOG("%s", "WLI_Init called!");
		InitializeCriticalSection(&g_wlidSvcReadyCritSect);
		g_tlsIsImpersonatedIdx = TlsAlloc();

		{
			util::critsect_t cs{&g_wlidSvcReadyCritSect};
			if (g_hWlidSvcReady == NULL)
			{
				g_hWlidSvcReady = CreateEvent(NULL, TRUE, FALSE, WLIDSVC_READY_EVENT);
			}
		}

		SetEvent(g_hWlidSvcReady);

		return TRUE;
	}

	BOOL WLI_Deinit(DWORD_PTR hContext)
	{
		return FALSE;
	}

	DWORD_PTR WLI_Open(DWORD_PTR hContext, DWORD dwAccess, DWORD dwShareMode)
	{
		return (DWORD_PTR)(new (std::nothrow) wlidsvc::handle_ctx_t(InterlockedIncrement(&g_instanceCount)));
	}

	BOOL WLI_Close(DWORD_PTR hContext)
	{
		delete ((wlidsvc::handle_ctx_t *)hContext);
		return TRUE;
	}

	DWORD WLI_Write(DWORD_PTR hContext, LPCVOID pInBuf, DWORD dwInLen)
	{
		return (DWORD)-1;
	}

	DWORD WLI_Read(DWORD_PTR hContext, LPVOID pBuf, DWORD dwLen)
	{
		return (DWORD)-1;
	}

	BOOL WLI_IOControl(DWORD_PTR hContext, DWORD dwCode, PBYTE pBufIn,
					   DWORD dwLenIn, PBYTE pBufOut, DWORD dwLenOut,
					   PDWORD pdwActualOut)
	{
		//LOG("WLI_IOControl %08x got IOCTL %04x", hContext, dwCode);

		BEGIN_IOCTL_MAP()
		IOCTL_HANDLER(IOCTL_WLIDSVC_LOG_MESSAGE, WLI_HandleLogMessage)
		IOCTL_HANDLER(IOCTL_WLIDSVC_LOG_MESSAGE_WIDE, WLI_HandleLogMessageWide)
		IOCTL_HANDLER(IOCTL_WLIDSVC_INIT_HANDLE, WLI_InitHandle);
		IOCTL_HANDLER(IOCTL_WLIDSVC_GET_DEFAULT_ID, WLI_GetDefaultID);
		IOCTL_HANDLER(IOCTL_WLIDSVC_CREATE_IDENTITY_HANDLE, WLI_CreateIdentityHandle);
		IOCTL_HANDLER(IOCTL_WLIDSVC_CLOSE_IDENTITY_HANDLE, WLI_CloseIdentityHandle);
		END_IOCTL_MAP()
		return FALSE;
	}

	DWORD WLI_Seek(DWORD_PTR hContext, long pos, DWORD type)
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