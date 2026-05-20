#pragma once

#include <vector>
#include <string>

#include <types.h>
#include <storage.h>
#include <microrest.h>

// TODO: we should have fully typed requests/responses really

namespace wlidsvc::rest
{
    struct reliveid_client_t
    {
    public:
        reliveid_client_t(identity_ctx_t *id_ctx) : ctx(id_ctx)
        {
        }

        HRESULT post(std::string endpoint, std::string data, net::result_t &result)
        {
            std::vector<std::string> additional_headers{};
            if (ctx->use_sts_token)
            {
                token_t token;
                storage::token_store_t token_store{storage::db_path()};
                if (token_store.retrieve(ctx->member_name, L"http://Passport.NET/tb", token))
                    additional_headers.push_back("Authorization: Bearer " + token.token);
                else
                    LOG("%s", "Request called for STS token, none was found.");
            }

            LOG("Sending POST request: %s %s", endpoint.c_str(), data.c_str());
            
            result = client.post(endpoint, data, "application/json", additional_headers);
            if (!result.ok())
            {
                return HRESULT_FROM_CURLE(result.curl_error);
            }

            LOG("Received response: %s", result.body.c_str());

            if (result.status_code != 200 && result.status_code != 401)
            {
                LOG("Request failed with status code %ld", result.status_code);
                return HRESULT_FROM_HTTP(result.status_code);
            }

            return S_OK;
        }

    private:
        net::client_t client;
        identity_ctx_t *ctx;
    };

}