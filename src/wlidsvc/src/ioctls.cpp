#include <windows.h>
#include "ioctls.h"
#include "log.h"

BOOL WLI_HandleLogMessage(
    DWORD hContext, PBYTE pBufIn, DWORD dwLenIn,
    PBYTE pBufOut, DWORD dwLenOut, PDWORD pdwActualOut)
{
    if (pBufIn == NULL || dwLenIn == 0)
    {
        return E_INVALIDARG;
    }

    wlidsvc::log::info().log("[%08x] %s", hContext, pBufIn);

    return S_OK;
}

BOOL WLI_HandleLogMessageWide(
    DWORD hContext, PBYTE pBufIn, DWORD dwLenIn,
    PBYTE pBufOut, DWORD dwLenOut, PDWORD pdwActualOut)
{
    if (pBufIn == NULL || dwLenIn == 0)
    {
        return E_INVALIDARG;
    }

    const char *tmp = wchar_to_char((const wchar_t *)pBufIn);

    wlidsvc::log::info().log(L"[%08x] %s", hContext, tmp);

    delete[] tmp;

    return S_OK;
}