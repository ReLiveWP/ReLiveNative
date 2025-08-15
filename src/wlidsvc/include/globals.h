#pragma once
#include <windows.h>
#include <map>
#include <memory>
#include "types.h"

namespace wlidsvc::globals
{
    extern long g_instanceCount;
    extern HANDLE g_hWlidSvcReady;
    extern CRITICAL_SECTION g_wlidSvcReadyCritSect;
    extern DWORD g_tlsIsImpersonatedIdx;
    extern BOOL g_ClientConfigReady;
    extern BOOL g_ClientConfigDownloading;
    extern HANDLE g_ClientConfigDownloadedEvent;
    extern CRITICAL_SECTION g_ClientConfigCritSect;
    extern CRITICAL_SECTION g_dbCritSect;
}