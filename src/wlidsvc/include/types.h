#pragma once
#include <string>
#include <string_view>
#include <vector>
#include <curl/curl.h>
#include <sqlite3.h>

namespace wlidsvc
{
    struct handle_ctx_t;

    struct identity_ctx_t
    {
        inline identity_ctx_t(handle_ctx_t *lpHandleCtx, LPWSTR szMemberName, DWORD dwFlags)
            : handle_ctx(lpHandleCtx), member_name(szMemberName), flags(dwFlags), curl_multi(nullptr), sqlite(nullptr)
        {
            curl_multi = curl_multi_init();
        }

        inline ~identity_ctx_t()
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

        handle_ctx_t *handle_ctx;
        std::wstring member_name;
        DWORD flags;

        CURLM *curl_multi;
        sqlite3 *sqlite;
    };

    struct handle_ctx_t
    {
        inline handle_ctx_t(DWORD _hThis) : hThis(_hThis)
        {
        }

        inline ~handle_ctx_t()
        {
            for (auto identity : associated_identities)
            {
                delete identity;
            }
        }

        DWORD hThis;
        GUID app;
        DWORD major_version;
        DWORD minor_version;
        std::wstring exec_path;
        std::vector<identity_ctx_t *> associated_identities;
    };
}