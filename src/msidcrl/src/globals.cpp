#include "globals.h"

namespace msidcrl::globals
{
    HANDLE g_hDriver = NULL;
    CRITICAL_SECTION g_hDriverCrtiSec = {};
}