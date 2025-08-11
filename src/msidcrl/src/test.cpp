#include <windows.h>
#include "wlidcomm.h"

#ifdef UNDER_CE
#undef GetProcAddress
#define GetProcAddress(hInst, x) GetProcAddressW(hInst, TEXT(x))
#endif

extern "C"
{
    HANDLE g_wliFile = NULL;
#if IS_TESTING
    HMODULE g_hWlidSvc = NULL;
    typedef DWORD_PTR (*WLI_Init)(DWORD_PTR hContext);
    typedef DWORD_PTR (*WLI_Open)(DWORD_PTR hContext, DWORD dwAccess, DWORD dwShareMode);
    typedef BOOL (*WLI_Close)(DWORD_PTR hContext);
    typedef BOOL (*WLI_IOControl)(DWORD_PTR hContext, DWORD dwCode, PBYTE pBufIn,
                                  DWORD dwLenIn, PBYTE pBufOut, DWORD dwLenOut,
                                  PDWORD pdwActualOut);

    WLI_Init WLI_Init = NULL;
    WLI_Open WLI_Open = NULL;
    WLI_Close WLI_Close = NULL;
    WLI_IOControl WLI_IOControl = NULL;

#elif WLIDSVC_INPROC
    DWORD_PTR WLI_Init(DWORD_PTR hContext);
    BOOL WLI_Deinit(DWORD_PTR hContext);
    DWORD_PTR WLI_Open(DWORD_PTR hContext, DWORD dwAccess, DWORD dwShareMode);
    BOOL WLI_Close(DWORD_PTR hContext);
    DWORD WLI_Write(DWORD_PTR hContext, LPCVOID pInBuf, DWORD dwInLen);
    DWORD WLI_Read(DWORD_PTR hContext, LPVOID pBuf, DWORD dwLen);
    BOOL WLI_IOControl(DWORD_PTR hContext, DWORD dwCode, PBYTE pBufIn,
                       DWORD dwLenIn, PBYTE pBufOut, DWORD dwLenOut,
                       PDWORD pdwActualOut);
    DWORD WLI_Seek(DWORD_PTR hContext, long pos, DWORD type);
    void WLI_PowerUp(void);
    void WLI_PowerDown(void);
#endif
    void TEST_InitHooks(void)
    {
#if IS_TESTING
        g_hWlidSvc = LoadLibrary(TEXT("wlidsvc"));
        WLI_Init = (WLI_Init)GetProcAddress(g_hWlidSvc, "WLI_Init");
        WLI_Open = (WLI_Open)GetProcAddress(g_hWlidSvc, "WLI_Open");
        WLI_Close = (WLI_Close)GetProcAddress(g_hWlidSvc, "WLI_Close");
        WLI_IOControl = (WLI_IOControl)GetProcAddress(g_hWlidSvc, "WLI_IOControl");

        (WLI_Init)(0);
#elif WLIDSVC_INPROC
        WLI_Init(0);
#endif
    }

#if IS_TESTING || WLIDSVC_INPROC
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

            return (g_wliFile = (HANDLE)WLI_Open(0, dwDesiredAccess, dwShareMode));
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
            return WLI_IOControl((DWORD_PTR)hDevice, dwIoControlCode, (PBYTE)lpInBuffer, nInBufferSize, (PBYTE)lpOutBuffer, nOutBufferSize, lpBytesReturned);
        }

        return DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped);
    }

    BOOL CloseHandle_TestHook(HANDLE hDevice)
    {
        if (hDevice == g_wliFile && hDevice != NULL)
        {
            return WLI_Close((DWORD_PTR)hDevice);
        }

        return CloseHandle(hDevice);
    }
#endif
}