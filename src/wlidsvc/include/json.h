#pragma once

#define JSON_HAS_FILESYSTEM 0
#define JSON_HAS_EXPERIMENTAL_FILESYSTEM 0

#include <cerrno>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace wlidsvc::rest
{
    namespace types
    {
        struct user_identity_t;
        struct security_token_t;
        struct security_token_request_t;
        struct security_tokens_request_t;
        struct security_tokens_response_t;
        struct fetch_cert_request_t;
        struct fetch_cert_response_t;
        struct register_device_request_t;
        struct register_device_response_t;

        void to_json(json &j, const user_identity_t &t);
        void from_json(const json &j, user_identity_t &t);
        void to_json(json &j, const security_token_t &t);
        void from_json(const json &j, security_token_t &t);
        void to_json(json &j, const fetch_cert_request_t &t);
        void from_json(const json &j, fetch_cert_response_t &t);
        void to_json(json &j, const register_device_request_t &t);
        void from_json(const json &j, register_device_response_t &t);
        void to_json(json &j, const security_token_request_t &t);
        void to_json(json &j, const security_tokens_request_t &t);
        void from_json(const json &j, security_tokens_response_t &t);
    }
}