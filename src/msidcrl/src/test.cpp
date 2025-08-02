#include <windows.h>
#include "wlidcomm.h"

#ifdef UNDER_CE
#undef GetProcAddress
#define GetProcAddress(hInst, x) GetProcAddressW(hInst, TEXT(x))
#endif

extern "C"
{
#if IS_TESTING
    typedef DWORD_PTR (*WLI_Init)(DWORD_PTR hContext);
    typedef DWORD_PTR (*WLI_Open)(DWORD_PTR hContext, DWORD dwAccess, DWORD dwShareMode);
    typedef BOOL (*WLI_Close)(DWORD_PTR hContext);
    typedef BOOL (*WLI_IOControl)(DWORD_PTR hContext, DWORD dwCode, PBYTE pBufIn,
                                  DWORD dwLenIn, PBYTE pBufOut, DWORD dwLenOut,
                                  PDWORD pdwActualOut);

    HMODULE g_hWlidSvc = NULL;
    HANDLE g_wliFile = NULL;
    WLI_Init g_WLI_Init = NULL;
    WLI_Open g_WLI_Open = NULL;
    WLI_Close g_WLI_Close = NULL;
    WLI_IOControl g_WLI_IOControl = NULL;
#endif
    void TEST_InitHooks(void)
    {
#if IS_TESTING
        g_hWlidSvc = LoadLibrary(TEXT("wlidsvc"));
        g_WLI_Init = (WLI_Init)GetProcAddress(g_hWlidSvc, "WLI_Init");
        g_WLI_Open = (WLI_Open)GetProcAddress(g_hWlidSvc, "WLI_Open");
        g_WLI_Close = (WLI_Close)GetProcAddress(g_hWlidSvc, "WLI_Close");
        g_WLI_IOControl = (WLI_IOControl)GetProcAddress(g_hWlidSvc, "WLI_IOControl");

        (g_WLI_Init)(0);
#endif
    }

#if IS_TESTING
    HANDLE CreateFile_TestHook(
        LPCWSTR lpFileName,
        DWORD dwDesiredAccess,
        DWORD dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD dwCreationDisposition,
        DWORD dwFlagsAndAttributes,
        HANDLE hTemplateFile)
    {
        if (wcscmp(WLIDSVC_FILE, lpFileName) == 0)
        {
            if (g_wliFile != NULL)
                return g_wliFile;

            return (g_wliFile = (HANDLE)g_WLI_Open(0, dwDesiredAccess, dwShareMode));
        }

        return CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }

    BOOL DeviceIoControl_TestHook(
        HANDLE hDevice,
        DWORD dwIoControlCode,
        LPVOID lpInBuffer,
        DWORD nInBufferSize,
        LPVOID lpOutBuffer,
        DWORD nOutBufferSize,
        LPDWORD lpBytesReturned,
        LPOVERLAPPED lpOverlapped)
    {
        if (hDevice == g_wliFile && hDevice != NULL)
        {
            return g_WLI_IOControl((DWORD_PTR)hDevice, dwIoControlCode, (PBYTE)lpInBuffer, nInBufferSize, (PBYTE)lpOutBuffer, nOutBufferSize, lpBytesReturned);
        }

        return DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped);
    }

    BOOL CloseHandle_TestHook(HANDLE hDevice)
    {
        if (hDevice == g_wliFile && hDevice != NULL)
        {
            return g_WLI_Close((DWORD_PTR)hDevice);
        }

        return CloseHandle(hDevice);
    }
#endif
}