#include "types.h"

#include <curl/curl.h>
#include <sqlite3.h>

namespace wlidsvc
{
    identity_ctx_t::identity_ctx_t(handle_ctx_t *lpHandleCtx, LPWSTR szMemberName, DWORD dwFlags)
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