
#include <windows.h>

#define WINAPI __stdcall

extern "C"
{
	DWORD WINAPI WLI_Init(DWORD dwData)
	{
		return (DWORD)TRUE;
	}

	BOOL WINAPI WLI_Deinit(DWORD dwData)
	{
		return FALSE;
	}

	DWORD WINAPI WLI_Open(DWORD dwData, DWORD dwAccess, DWORD dwShareMode)
	{
		return (DWORD)TRUE;
	}

	BOOL WINAPI WLI_Close(DWORD dwData)
	{
		return TRUE;
	}

	DWORD WINAPI WLI_Write(DWORD dwData, LPCVOID pInBuf, DWORD dwInLen)
	{
		return (DWORD)-1;
	}

	DWORD WINAPI WLI_Read(DWORD dwData, LPVOID pBuf, DWORD dwLen)
	{
		return (DWORD)-1;
	}

	BOOL WINAPI WLI_IOControl(DWORD dwData, DWORD dwCode, PBYTE pBufIn,
				  DWORD dwLenIn, PBYTE pBufOut, DWORD dwLenOut,
				  PDWORD pdwActualOut)
	{
		return FALSE;
	}

	DWORD WINAPI WLI_Seek(DWORD dwData, long pos, DWORD type)
	{
		return (DWORD)-1;
	}

	void WINAPI WLI_PowerUp(void)
	{
		return;
	}

	void WINAPI WLI_PowerDown(void)
	{
		return;
	}
}