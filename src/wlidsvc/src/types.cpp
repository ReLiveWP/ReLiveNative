#include "types.h"
#include "log.h"

#include <curl/curl.h>
#include <sqlite3.h>

namespace wlidsvc
{
    bool token_t::is_valid() const
    {
        if (invalid)
            return false;

        // if (!expires.empty())
        // {
        //     int year, mon, day, hour, min, sec;
        //     if (sscanf(expires.c_str(), "%d-%d-%dT%d:%d:%d", &year, &mon, &day, &hour, &min, &sec) == 6)
        //     {
        //         SYSTEMTIME st{};
        //         st.wYear   = (WORD)year;
        //         st.wMonth  = (WORD)mon;
        //         st.wDay    = (WORD)day;
        //         st.wHour   = (WORD)hour;
        //         st.wMinute = (WORD)min;
        //         st.wSecond = (WORD)sec;

        //         FILETIME ft{};
        //         if (!SystemTimeToFileTime(&st, &ft))
        //             return true; // unparseable expiry — assume valid

        //         // apply timezone offset (+HH:MM or -HH:MM) to get UTC
        //         const char *p = expires.c_str() + 19;
        //         while (*p && *p != '+' && *p != '-') ++p;
        //         if (*p)
        //         {
        //             int sign = (*p == '+') ? 1 : -1;
        //             int tz_h = 0, tz_m = 0;
        //             sscanf(p + 1, "%d:%d", &tz_h, &tz_m);

        //             ULARGE_INTEGER uli;
        //             uli.LowPart  = ft.dwLowDateTime;
        //             uli.HighPart = ft.dwHighDateTime;
        //             uli.QuadPart -= (LONGLONG)sign * (tz_h * 3600LL + tz_m * 60LL) * 10000000LL;
        //             ft.dwLowDateTime  = uli.LowPart;
        //             ft.dwHighDateTime = uli.HighPart;
        //         }

        //         FILETIME now{};
        //         GetSystemTimeAsFileTime(&now);

        //         if (CompareFileTime(&ft, &now) <= 0)
        //             return false;
        //     }
        // }

        return true;
    }

    identity_ctx_t::identity_ctx_t(handle_ctx_t *lpHandleCtx, LPCWSTR szMemberName, DWORD dwFlags)
        : handle_ctx(lpHandleCtx),
          member_name(szMemberName),
          flags(dwFlags),
          is_authenticated(false),
          curl_multi(nullptr),
          sqlite(nullptr),
          credentials(),
          use_sts_token(true)
    {
        curl_multi = curl_multi_init();
        if (curl_multi == nullptr)
            LOG("%s", "curl_multi_init failed");
    }

    identity_ctx_t::~identity_ctx_t()
    {
        if (curl_multi != nullptr)
        {
            curl_multi_cleanup(curl_multi);
            curl_multi = nullptr;
        }

        if (sqlite != nullptr)
        {
            sqlite3_close(sqlite);
            sqlite = nullptr;
        }
    }

    handle_ctx_t::handle_ctx_t(DWORD _hThis)
        : hThis(_hThis), major_version(0), minor_version(0), exec_path(L""), associated_identities()
    {
        InitializeCriticalSection(&cs);
    }

    handle_ctx_t::~handle_ctx_t()
    {
        DeleteCriticalSection(&cs);
        for (auto identity : associated_identities)
        {
            delete identity;
        }
    }
}