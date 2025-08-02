#pragma once
#include <windows.h>

namespace msidcrl::globals
{
    extern HANDLE g_hDriver;
    extern CRITICAL_SECTION g_hDriverCrtiSec;
}