#pragma once
#include "globals.h"

#ifndef _NO_LOGGING
#define LOG_MESSAGE(msg)                                                                                                              \
    do                                                                                                                                \
    {                                                                                                                                 \
        ::EnterCriticalSection(&msidcrl::globals::g_hDriverCrtiSec);                                                                  \
        if (msidcrl::globals::g_hDriver)                                                                                                                \
        {                                                                                                                             \
            WCHAR data[512];                                                                                                          \
            ::wsprintfW(data, L"%s",                                                                                                  \
                        msg);                                                                                                         \
            ::DeviceIoControl(msidcrl::globals::g_hDriver, IOCTL_WLIDSVC_LOG_MESSAGE_WIDE, (LPVOID *)data, 512, NULL, 0, NULL, NULL); \
        }                                                                                                                             \
        ::LeaveCriticalSection(&msidcrl::globals::g_hDriverCrtiSec);                                                                  \
    } while (0);

#define LOG_MESSAGE_FMT(fmt, ...)                                                                                           \
    do                                                                                                                      \
    {                                                                                                                       \
        ::EnterCriticalSection(&msidcrl::globals::g_hDriverCrtiSec);                                                        \
        if (msidcrl::globals::g_hDriver)                                                                                                      \
        {                                                                                                                   \
            WCHAR data[512];                                                                                                \
            ::wsprintfW(data, fmt, __VA_ARGS__);                                                                            \
            ::DeviceIoControl(msidcrl::globals::g_hDriver, IOCTL_WLIDSVC_LOG_MESSAGE_WIDE, data, 512, NULL, 0, NULL, NULL); \
        }                                                                                                                   \
        ::LeaveCriticalSection(&msidcrl::globals::g_hDriverCrtiSec);                                                        \
    } while (0);

#define LOG_STRING(str) (str == NULL ? TEXT("!!NULL!!") : str)
#else
#define LOG_MESSAGE(msg)
#define LOG_MESSAGE_FMT(fmt, ...)
#define LOG_STRING(str)
#endif