#pragma once
#include <windows.h>
#include <string>
#include <map>
#include <vector>
#include <cstdint>

struct sqlite3;
typedef void CURLM;

namespace wlidsvc
{
    struct handle_ctx_t;
    struct identity_ctx_t;

    struct identity_t
    {
        std::string identity;
        uint64_t puid;
        std::string cuid;
        std::string email;
        std::string display_name;
    };

    struct token_t
    {
        std::string identity;
        std::string service;
        std::string token;
        std::string type; // "JWT", "X509v3", etc.
        std::string expires; // ISO 8601 format
        std::string created; // ISO 8601 format
    };

    struct identity_ctx_t
    {
        identity_ctx_t(handle_ctx_t *lpHandleCtx, LPWSTR szMemberName, DWORD dwFlags);
        ~identity_ctx_t();

        handle_ctx_t *handle_ctx;
        std::wstring member_name;
        DWORD flags;

        std::map<std::wstring, std::wstring> properties;
        std::map<std::wstring, std::wstring> credentials;

        CURLM *curl_multi;
        sqlite3 *sqlite;
    };

    struct handle_ctx_t
    {
        handle_ctx_t(DWORD _hThis);
        ~handle_ctx_t();

        DWORD hThis;
        GUID app;
        DWORD major_version;
        DWORD minor_version;
        std::wstring exec_path;
        std::vector<identity_ctx_t *> associated_identities;
    };
}