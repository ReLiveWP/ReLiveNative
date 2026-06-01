#pragma once

#include <vector>
#include <map>
#include <string>

#include <types.h>
#include <storage.h>
#include <microrest.h>
#include <urls.h>

// TODO: we should have fully typed requests/responses really

namespace wlidsvc::rest
{
    namespace types
    {
        struct user_identity_t
        {
            std::string id;
            std::string cid;
            std::int64_t puid;
            std::string username;
            std::string email_address;

            identity_t to_identity() const
            {
                identity_t identity{
                    .identity = username,
                    .puid = puid,
                    .cid = cid,
                    .email = email_address};

                return identity;
            }
        };

        struct security_token_t
        {
            std::string service_target;
            std::string token;
            std::string token_type;
            std::string created;
            std::string expires;

            token_t to_token(std::string identity) const
            {
                token_t t{
                    .identity = identity,
                    .service = service_target,
                    .token = token,
                    .type = token_type,
                    .created = created,
                    .expires = expires};

                return t;
            }
        };

        struct security_token_request_t
        {
            std::string service_target;
            std::string service_policy;
        };

        struct security_tokens_request_t
        {
            std::string identity;
            std::map<std::string, std::string> credentials;
            std::vector<security_token_request_t> token_requests;
        };

        struct security_tokens_response_t
        {
            std::int64_t puid;
            std::string cid;
            std::string username;
            std::string email_address;
            std::vector<security_token_t> security_tokens;
        };

        struct fetch_cert_request_t
        {
            std::string csr;
        };

        struct fetch_cert_response_t
        {
            std::string device_cert;
        };

        struct register_device_request_t
        {
            std::string username;
            std::string password;
            std::string device_id;
        };

        struct register_device_response_t
        {
            user_identity_t identity;
            std::vector<security_token_t> security_tokens;
        };
    }

    struct error_t
    {
        inline error_t(HRESULT _hr) : hr(_hr)
        {
        }

        inline const bool ok() const
        {
            return SUCCEEDED(hr);
        }

        inline const bool failed() const
        {
            return FAILED(hr);
        }

        HRESULT hr;
    };

    struct reliveid_client_t
    {
    public:
        reliveid_client_t(identity_ctx_t *id_ctx) : ctx(id_ctx)
        {
        }

        error_t request_security_tokens(const types::security_tokens_request_t &req, types::security_tokens_response_t &resp);
        error_t register_device(const types::register_device_request_t &req, types::register_device_response_t &resp);
        error_t fetch_certificate(const types::fetch_cert_request_t &req, types::fetch_cert_response_t &resp);

        HRESULT post(std::string_view endpoint, std::string_view data, net::result_t &result);

    private:
        net::client_t client;
        identity_ctx_t *ctx;

        template <typename TRequest, typename TResponse>
        error_t fetch(const std::string_view endpoint, const TRequest &req, TResponse &resp);
    };

}