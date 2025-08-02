#include "globals.h"
#include "util.h"

namespace wlidsvc::globals
{
    long g_instanceCount = 0;
    HANDLE g_hWlidSvcReady = NULL;
    CRITICAL_SECTION g_wlidSvcReadyCritSect = {};
    DWORD g_tlsIsImpersonatedIdx = -1;
}
