#pragma once
#include <string>
#include <string_view>
#include <curl/curl.h>

namespace wlidsvc
{
    struct handle_ctx_t
    {
        inline handle_ctx_t(DWORD _hThis) : hThis(_hThis)
        {
            this->curl = curl_multi_init();
        }

        inline ~handle_ctx_t()
        {
            curl_multi_cleanup(this->curl);
        }

        DWORD hThis;
        GUID app;
        DWORD major_version;
        DWORD minor_version;
        std::wstring exec_path;

        CURLM *curl;
    };
}