#pragma once
#include <string>
#include <string_view>
#include <vector>
#include <curl/curl.h>

namespace wlidsvc
{
    struct identity_ctx_t
    {
        inline identity_ctx_t(LPWSTR szMemberName, DWORD dwFlags) : member_name(szMemberName), flags(dwFlags) {}
        inline ~identity_ctx_t() {}

        std::wstring member_name;
        DWORD flags;
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