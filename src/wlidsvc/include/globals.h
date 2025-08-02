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
}