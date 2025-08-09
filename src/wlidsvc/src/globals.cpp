#include "globals.h"
#include "util.h"

namespace wlidsvc::globals
{
    long g_instanceCount = 0;
    HANDLE g_hWlidSvcReady = NULL;
    CRITICAL_SECTION g_wlidSvcReadyCritSect = {};
    BOOL g_ClientConfigReady = FALSE;
    BOOL g_ClientConfigDownloading = FALSE;
    HANDLE g_ClientConfigDownloadedEvent = NULL;
    CRITICAL_SECTION g_ClientConfigCritSect{};
    DWORD g_tlsIsImpersonatedIdx = -1;
}
