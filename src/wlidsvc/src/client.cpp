#include <client.h>

#include "json.h"

namespace wlidsvc::rest
{
    error_t reliveid_client_t::request_security_tokens(const types::security_tokens_request_t &req, types::security_tokens_response_t &resp)
    {
        constexpr std::string_view endpoint = config::g_requestTokensEndpoint;

        return fetch(endpoint, req, resp);
    }

    error_t reliveid_client_t::register_device(const types::register_device_request_t &req, types::register_device_response_t &resp)
    {
        constexpr std::string_view endpoint = config::g_registerDeviceEndpoint;

        return fetch(endpoint, req, resp);
    }

    error_t reliveid_client_t::fetch_certificate(const types::fetch_cert_request_t &req, types::fetch_cert_response_t &resp)
    {
        constexpr std::string_view endpoint = config::g_provisionDeviceEndpoint;

        return fetch(endpoint, req, resp);
    }

    template <typename TRequest, typename TResponse>
    error_t reliveid_client_t::fetch(const std::string_view endpoint, const TRequest &req, TResponse &resp)
    {
        HRESULT hr;

        json j = req;
        net::result_t result{};
        if (FAILED(hr = post(endpoint, j.dump(), result)))
        {
            return hr;
        }

        auto response = json::parse(result.body, nullptr, false);
        if (response.is_discarded())
        {
            LOG("request failed, invalid JSON %s", result.body.c_str());
            return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        }

        if (response["error_code"].is_number_integer())
        {
            // server reported an error
            if (FAILED(hr = response["error_code"].get<HRESULT>()))
            {
                LOG("request failed, server returned hr=0x%08x", hr);
                return hr;
            }
        }

        if (result.status_code != 200)
        {
            // TODO: more error parsing
            LOG("request failed, status code %d", result.status_code);
            return HRESULT_FROM_HTTP(result.status_code);
        }

        resp = response.get<TResponse>();

        return S_OK;
    }

    HRESULT reliveid_client_t::post(std::string_view endpoint, std::string_view data, net::result_t &result)
    {
        std::vector<std::string> additional_headers{};
        if (ctx && ctx->use_sts_token)
        {
            token_t token;
            storage::token_store_t token_store{storage::db_path()};
            if (token_store.retrieve(ctx->member_name, L"http://Passport.NET/tb", token) && token.is_valid())
                additional_headers.push_back("Authorization: Bearer " + token.token);
            else
                LOG("%s", "Request called for STS token, none was found or it is invalid.");
        }

        LOG("Sending POST request: %s %s", endpoint.data(), data.data());

        result = client.post(endpoint, data, "application/json", additional_headers);
        if (!result.success())
        {
            LOG("Request failed with curl code %ld", result.curl_error);
            return HRESULT_FROM_CURLE(result.curl_error);
        }

        LOG("Received response: %s", result.body.data());
        if (result.status_code != 200 && result.status_code != 401)
        {
            LOG("Request failed with status code %ld", result.status_code);
            return HRESULT_FROM_HTTP(result.status_code);
        }

        return S_OK;
    }

    namespace types
    {
        void to_json(json &j, const user_identity_t &t)
        {
            j = json{{"id", t.id},
                     {"cid", t.cid},
                     {"puid", t.puid},
                     {"username", t.username},
                     {"email_address", t.email_address}};
        }

        void from_json(const json &j, user_identity_t &t)
        {
            j.at("id").get_to(t.id);
            j.at("cid").get_to(t.cid);
            j.at("puid").get_to(t.puid);
            j.at("username").get_to(t.username);
            j.at("email_address").get_to(t.email_address);
        }

        void to_json(json &j, const security_token_t &t)
        {
            j = json{{"service_target", t.service_target},
                     {"token", t.token},
                     {"token_type", t.token_type},
                     {"created", t.created},
                     {"expires", t.expires}};
        }

        void from_json(const json &j, security_token_t &t)
        {
            j.at("service_target").get_to(t.service_target);
            j.at("token").get_to(t.token);
            j.at("token_type").get_to(t.token_type);
            j.at("created").get_to(t.created);
            j.at("expires").get_to(t.expires);
        }

        void to_json(json &j, const fetch_cert_request_t &t)
        {
            j = json{{"csr", t.csr}};
        }

        void from_json(const json &j, fetch_cert_response_t &t)
        {
            j.at("device_cert").get_to(t.device_cert);
        }

        void to_json(json &j, const register_device_request_t &t)
        {
            j = json{{"username", t.username}, {"password", t.password}, {"device_id", t.device_id}};
        }

        void from_json(const json &j, register_device_response_t &t)
        {
            j.at("identity").get_to(t.identity);
            j.at("security_tokens").get_to(t.security_tokens);
        }

        void to_json(json &j, const security_token_request_t &t)
        {
            j = json{{"service_policy", t.service_policy}, {"service_target", t.service_target}};
        }

        void to_json(json &j, const security_tokens_request_t &t)
        {
            j = json{
                {"identity", t.identity},
                {"credentials", t.credentials},
                {"token_requests", t.token_requests}};
        }

        void from_json(const json &j, security_tokens_response_t &t)
        {
            j.at("puid").get_to(t.puid);
            j.at("cid").get_to(t.cid);
            j.at("username").get_to(t.username);
            j.at("email_address").get_to(t.email_address);
            j.at("security_tokens").get_to(t.security_tokens);
        }
    }
}