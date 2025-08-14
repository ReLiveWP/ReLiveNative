#include <windows.h>
#include <objbase.h>
#include <wlidcomm.h>
#include "ioctls.h"
#include "log.h"
#include "util.h"
#include "globals.h"
#include "microrest.h"
#include "config.h"
#include "urls.h"
#include "storage.h"

#include <algorithm>

#include <cerrno>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

using namespace wlidsvc;
using namespace wlidsvc::net;
using namespace wlidsvc::storage;
using namespace wlidsvc::config;

#define IMPERSONATE_DEFAULT_POLICY "WLIDSVC"
#define IMPERSONATE_USERAPI_POLICY "WLIDSVCCAPUSERAPI"

#define SERVICE_TOKEN_FROM_CACHE 0x00010000

#define IMPERSONATE_DECL() \
    HRESULT __imp_hr;      \
    util::impersonate_t __imp_impersonate{};

#define IMPERSONATE(policy)                                               \
    if (FAILED(__imp_hr = __imp_impersonate.verify_policy(TEXT(policy)))) \
    {                                                                     \
        LOG("verify_policy() failed: 0x%08x;", __imp_hr);                 \
        return __imp_hr;                                                  \
    }                                                                     \
                                                                          \
    if (FAILED(__imp_hr = __imp_impersonate.impersonate()))               \
    {                                                                     \
        LOG("impersonate() failed: 0x%08x;", __imp_hr);                   \
        return __imp_hr;                                                  \
    }

#define PPCRL_REQUEST_E_MISSING_PRIMARY_CREDENTIAL 0x8004882e

HRESULT DeserializeRSTParams(GUID gMapParams, DWORD dwSize, LPBYTE *ppBuffer, RSTParams **ppParams)
{
    if (ppBuffer == nullptr || ppParams == nullptr)
    {
        LOG("%s", "Invalid arguments: ppBuffer or ppParams is NULL");
        return E_INVALIDARG;
    }

    *ppBuffer = nullptr;
    *ppParams = nullptr;

    if (IsEqualGUID(gMapParams, GUID{0}))
    {
        LOG("%s", "GUID is empty, no parameters to deserialize.");
        return S_FALSE;
    }

    WCHAR szGuid[40] = {0};
    StringFromGUID2(gMapParams, szGuid, 40);

    HANDLE hMap = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, dwSize, szGuid);
    if (hMap == NULL)
    {
        LOG("OpenFileMapping failed: %d", GetLastError());
        return HRESULT_FROM_WIN32(GetLastError());
    }

    BYTE *pMapView = (BYTE *)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (pMapView == NULL)
    {
        CloseHandle(hMap);
        LOG("MapViewOfFile failed: %d", GetLastError());
        return HRESULT_FROM_WIN32(GetLastError());
    }

    DWORD cbSize = *(DWORD *)pMapView;
    BYTE *pBuffer = new (std::nothrow) BYTE[cbSize];
    if (pBuffer == NULL)
    {
        UnmapViewOfFile(pMapView);
        CloseHandle(hMap);
        return E_OUTOFMEMORY;
    }

    std::memcpy(pBuffer, pMapView, cbSize);
    UnmapViewOfFile(pMapView);
    CloseHandle(hMap);

    // first 4 bytes are the total size, next 4 bytes are the parameter count
    HRESULT hr = E_NOTIMPL;
    DWORD dwParamCount = *(DWORD *)(pBuffer + 4);
    RSTParams *pParams = reinterpret_cast<RSTParams *>(pBuffer + 8);
    for (int i = 0; i < dwParamCount; ++i)
    {
        // fixup the pointers in the RSTParams structure
        RSTParams *pParam = &pParams[i];
        if (pParam->szServiceTarget != nullptr)
            pParam->szServiceTarget = reinterpret_cast<LPWSTR>((DWORD_PTR)pBuffer + (DWORD_PTR)pParam->szServiceTarget);
        if (pParam->szServicePolicy != nullptr)
            pParam->szServicePolicy = reinterpret_cast<LPWSTR>((DWORD_PTR)pBuffer + (DWORD_PTR)pParam->szServicePolicy);

        LOG("Param %d: ServiceTarget=%s, ServicePolicy=%s, TokenFlags=%d, TokenParam=%d",
            i,
            pParam->szServiceTarget ? util::wstring_to_utf8(pParam->szServiceTarget).c_str() : "NULL",
            pParam->szServicePolicy ? util::wstring_to_utf8(pParam->szServicePolicy).c_str() : "NULL",
            pParam->dwTokenFlags,
            pParam->dwTokenParam);
    }

    *ppBuffer = pBuffer;
    *ppParams = pParams;

    LOG("Deserialized %d parameters from the buffer.", dwParamCount);
    return S_OK;
}

HRESULT serialise_logon_request(identity_ctx_t *identityCtx, const std::string &auth_policy, const GUID &gMapParams, const DWORD dwFileSize, const DWORD dwParamCount, std::string &logon_data_str)
{
    HRESULT hr;
    json credentials = json::object();
    for (auto &&credential : identityCtx->credentials)
    {
        if (!(credential.first == L"ps:password" && credential.second.find_first_not_of('*') == std::wstring::npos))
            credentials[util::wstring_to_utf8(credential.first)] = util::wstring_to_utf8(credential.second);
    }

    if (credentials.size() == 0)
    {
        if (identityCtx->use_sts_token)
        {
            token_t token;
            token_store_t token_store{storage::db_path()};
            if (!token_store.retrieve(identityCtx->member_name, L"http://Passport.NET/tb", token))
            {
                LOG("No credentials set for identity %s, attempted to use Passport.NET, it doesn't exist.", util::wstring_to_utf8(identityCtx->member_name).c_str());
                return PPCRL_REQUEST_E_MISSING_PRIMARY_CREDENTIAL;
            }
        }
        else
        {
            LOG("No credentials set for identity %s", util::wstring_to_utf8(identityCtx->member_name).c_str());
            return PPCRL_REQUEST_E_MISSING_PRIMARY_CREDENTIAL;
        }
    }

    json token_requests = json::array();

    LPBYTE pBuffer = nullptr;
    RSTParams *pParams = nullptr;
    if (FAILED(hr = DeserializeRSTParams(gMapParams, dwFileSize, &pBuffer, &pParams)))
    {
        LOG("DeserializeRSTParams failed: 0x%08x", hr);
        return hr;
    }

    for (DWORD i = 0; i < dwParamCount; ++i)
    {
        RSTParams *param = &pParams[i];
        json token_request = {
            {"service_target", util::wstring_to_utf8(param->szServiceTarget)},
            {"service_policy", util::wstring_to_utf8(param->szServicePolicy)}};

        token_requests.push_back(token_request);
    }

    delete[] pBuffer;

    if (token_requests.size() == 0)
    {
        token_requests.push_back({
            {"service_target", "http://Passport.NET/tb"},
            {"service_policy", auth_policy},
        });
    }

    json logon_data = {
        {"identity", util::wstring_to_utf8(identityCtx->member_name)},
        {"credentials", credentials},
        {"token_requests", token_requests}};

    logon_data_str = logon_data.dump();
    return S_OK;
}

HRESULT parse_logon_response(identity_ctx_t *identityCtx, std::string &body)
{
    // {
    //   "puid": 12345,
    //   "cid": "asdf",
    //   "username": "asdf",
    //   "email_address": "asdf@live.com",
    //   "security_tokens": [
    //     {
    //       "service_target": "http://Passport.NET/tb",
    //       "token": "snip",
    //       "token_type": "JWT",
    //       "created": "2025-08-10T15:42:46.0775874+01:00",
    //       "expires": "2025-09-09T15:42:46.0775874+01:00"
    //     }
    //   ]
    // }

    auto response = json::parse(body, nullptr, false);
    if (response.is_discarded())
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    }

    if (response["error_code"].is_number_integer())
    {
        // server reported an error
        return response["error_code"].get<HRESULT>();
    }

    const auto &username = response["username"].get<std::string>();

    {
        identity_store_t identity_store{storage::db_path()};

        identity_t identity;
        identity.identity = util::wstring_to_utf8(identityCtx->member_name);
        identity.puid = response["puid"].get<uint64_t>();
        identity.cuid = response["cid"].get<std::string>();
        identity.email = response["email_address"].get<std::string>();
        identity.display_name = username;

        if (!identity_store.store(identity))
        {
            LOG("Failed to store identity: %s (PUID: %llu, CUID: %s, Email: %s)",
                identity.identity.c_str(),
                identity.puid,
                identity.cuid.c_str(),
                identity.email.c_str());

            return E_FAIL;
        }

        LOG("Stored identity: %s (PUID: %llu, CUID: %s, Email: %s)",
            identity.identity.c_str(),
            identity.puid,
            identity.cuid.c_str(),
            identity.email.c_str());
    }

    {
        if (!response.contains("security_tokens") || !response["security_tokens"].is_array())
        {
            LOG("No security tokens found in response for %s", username.c_str());
            return S_OK; // no tokens to store, but not an error
        }

        token_store_t token_store{storage::db_path()};

        const auto &tokens = response["security_tokens"];
        for (size_t i = 0; i < tokens.size(); i++)
        {
            const auto &token = tokens[i];

            token_t t;
            t.identity = util::wstring_to_utf8(identityCtx->member_name);
            t.service = token["service_target"].get<std::string>();
            t.token = token["token"].get<std::string>();
            t.type = token["token_type"].get<std::string>();
            t.created = token["created"].get<std::string>();
            t.expires = token["expires"].get<std::string>();

            if (!token_store.store(t))
            {
                LOG("Failed to store token for %s: %s (Type: %s, Expires: %s)",
                    username.c_str(),
                    t.service.c_str(),
                    t.type.c_str(),
                    t.expires.c_str());

                continue;
            }

            LOG("Stored token for %s: %s (Type: %s, Expires: %s)",
                username.c_str(),
                t.service.c_str(),
                t.type.c_str(),
                t.expires.c_str());
        }
    }

    {
        config_store_t cs{storage::db_path()};
        auto default_id = cs.get("DefaultID");
        if (default_id.empty())
        {
            cs.set(L"DefaultID", identityCtx->member_name);
        }
    }

    identityCtx->is_authenticated = true;

    return S_OK;
}

IOCTL_FUNC(HandleLogMessage)
{
    if (pBufIn == NULL || dwLenIn == 0)
        return E_INVALIDARG;

    LOG("LOGMSG [0x%08x] %s", hContext, pBufIn);

    return S_OK;
}

IOCTL_FUNC(HandleLogMessageWide)
{
    if (pBufIn == NULL || dwLenIn == 0)
        return E_INVALIDARG;

    const char *tmp = wchar_to_char((const wchar_t *)pBufIn);

    LOG_WIDE(L"LOGMSG [0x%08x] %s", hContext, tmp);

    delete[] tmp;

    return S_OK;
}

IOCTL_FUNC(InitHandle)
{
    IMPERSONATE_DECL();

    if (pBufIn == NULL || dwLenIn == 0)
        return E_INVALIDARG;

    VALIDATE_PARAMETER(dwLenIn != sizeof(IOCTL_INIT_HANDLE_ARGS));

    IMPERSONATE(IMPERSONATE_DEFAULT_POLICY);

    auto *pArgs = reinterpret_cast<PIOCTL_INIT_HANDLE_ARGS>(pBufIn);
    if (pArgs->dwApiLevel != WLIDSVC_API_LEVEL)
    {
        // binary mismatch between wlidsvc/msidcrl. should never happen.
        LOG(L"[0x%08x] %s", hContext, "API version mismatch detected! This should never happen!!");
        return E_UNEXPECTED;
    }

    std::memcpy(&hContext->app, &pArgs->gApp, sizeof(GUID));
    hContext->major_version = pArgs->dwMajorVersion;
    hContext->minor_version = pArgs->dwMinorVersion;
    hContext->exec_path = {pArgs->szExecutable};

    WCHAR lpGuid[40] = {0};
    StringFromGUID2(pArgs->gApp, lpGuid, 40);

    auto exec_path = util::wstring_to_utf8(hContext->exec_path);
    auto guid = util::wstring_to_utf8(std::wstring(lpGuid));
    LOG(L"[0x%08x] Initialized app %s, dwMajor: %d, dwMinor: %d, execPath: %s",
        hContext,
        guid.c_str(),
        pArgs->dwMajorVersion,
        pArgs->dwMinorVersion,
        exec_path.c_str());

    return S_OK;
}

IOCTL_FUNC(GetLiveEnvironment)
{
    IMPERSONATE_DECL();

    if (pBufOut == NULL || dwLenOut == 0)
        return E_INVALIDARG;

    VALIDATE_PARAMETER(dwLenOut != sizeof(IOCTL_GET_LIVE_ENVIRONMENT_RETURN));
    auto *pReturn = reinterpret_cast<PIOCTL_GET_LIVE_ENVIRONMENT_RETURN>(pBufOut);

    IMPERSONATE(IMPERSONATE_DEFAULT_POLICY);

    auto env = config::environment();
    pReturn->dwLiveEnv = (DWORD)env;

    return S_OK;
}

IOCTL_FUNC(GetDefaultID)
{
    HRESULT hr = S_OK;
    IOCTL_GET_DEFAULT_ID_RETURN data{};

    IMPERSONATE_DECL();
    IMPERSONATE(IMPERSONATE_USERAPI_POLICY);

    VALIDATE_PARAMETER(dwLenOut != sizeof(IOCTL_GET_DEFAULT_ID_RETURN));

    auto default_id = config::default_id();
    if (default_id.empty())
        return S_FALSE;

    VALIDATE_PARAMETER(default_id.size() >= 256);

    wcsncpy(data.szDefaultId, default_id.c_str(), 256);
    data.szDefaultId[default_id.size()] = '\0';

    std::memcpy(pBufOut, &data, sizeof(IOCTL_GET_DEFAULT_ID_RETURN));
    return hr;
}

IOCTL_FUNC(CreateIdentityHandle)
{
    HRESULT hr = S_OK;
    VALIDATE_PARAMETER(dwLenIn != sizeof(IOCTL_CREATE_IDENTITY_HANDLE_ARGS));
    VALIDATE_PARAMETER(dwLenOut != sizeof(IOCTL_CREATE_IDENTITY_HANDLE_RETURN));

    auto *pArgs = reinterpret_cast<PIOCTL_CREATE_IDENTITY_HANDLE_ARGS>(pBufIn);
    auto *pReturn = reinterpret_cast<PIOCTL_CREATE_IDENTITY_HANDLE_RETURN>(pBufOut);

    auto *identityCtx = new (std::nothrow) identity_ctx_t(hContext, pArgs->szMemberName, pArgs->dwIdentityFlags);
    if (identityCtx == nullptr)
        return E_OUTOFMEMORY;

    if (wcslen(pArgs->szMemberName) == 0)
    {
        identity_t identity;
        identity_store_t id_store{storage::db_path()};

        auto &default_id = config::default_id();
        auto default_id_utf8 = util::wstring_to_utf8(default_id);

        if (id_store.retrieve(default_id_utf8, identity))
        {
            LOG("Found default identity %s, setting member_name...", identity.identity.c_str());
            identityCtx->member_name = util::utf8_to_wstring(identity.identity);
        }
    }

    hContext->associated_identities.push_back(identityCtx);
    pReturn->hIdentity = (DWORD_PTR)identityCtx;

    return hr;
}

IOCTL_FUNC(CloseIdentityHandle)
{
    HRESULT hr = S_OK;
    VALIDATE_PARAMETER(dwLenIn != sizeof(IOCTL_CLOSE_IDENTITY_HANDLE_ARGS));

    auto *pArgs = reinterpret_cast<PIOCTL_CLOSE_IDENTITY_HANDLE_ARGS>(pBufIn);
    auto &identities = hContext->associated_identities;
    identity_ctx_t *identity = reinterpret_cast<identity_ctx_t *>(pArgs->hIdentity);

    identities.erase(std::remove(identities.begin(), identities.end(), identity), identities.end());

    delete identity;

    return hr;
}

IOCTL_FUNC(GetIdentityPropertyByName)
{
    VALIDATE_PARAMETER(dwLenIn != sizeof(IOCTL_GET_IDENTITY_PROPERTY_BY_NAME_ARGS));
    VALIDATE_PARAMETER(dwLenOut != sizeof(IOCTL_GET_IDENTITY_PROPERTY_BY_NAME_RETURN));

    auto *pArgs = reinterpret_cast<PIOCTL_GET_IDENTITY_PROPERTY_BY_NAME_ARGS>(pBufIn);
    auto *pReturn = reinterpret_cast<PIOCTL_GET_IDENTITY_PROPERTY_BY_NAME_RETURN>(pBufOut);

    auto *identityCtx = reinterpret_cast<identity_ctx_t *>(pArgs->hIdentity);
    if (identityCtx == nullptr)
        return E_INVALIDARG;

    // this seems wroooong? but it's expected by wlidux.dll#AsyncLogonIdentityExWithUI
    if (identityCtx->member_name.empty())
        return PPCRL_E_NO_MEMBER_NAME_SET;

    auto member_name_utf8 = util::wstring_to_utf8(identityCtx->member_name);

    {
        identity_t identity;
        identity_store_t id_store{storage::db_path()};

        if (!id_store.retrieve(member_name_utf8, identity))
            return E_UNEXPECTED;

        if (_wcsicmp(pArgs->szPropertyName, L"MemberName") == 0)
        {
            std::wstring member_name = util::utf8_to_wstring(identity.identity);

            VALIDATE_PARAMETER(member_name.size() >= 128);
            wcsncpy(pReturn->szPropertyValue, member_name.c_str(), 128);
            pReturn->szPropertyValue[member_name.size()] = '\0';

            return S_OK;
        }

        if (_wcsicmp(pArgs->szPropertyName, L"CID") == 0)
        {
            std::wstring cuid = util::utf8_to_wstring(identity.cuid);

            VALIDATE_PARAMETER(cuid.size() >= 128);
            wcsncpy(pReturn->szPropertyValue, cuid.c_str(), 128);
            pReturn->szPropertyValue[cuid.size()] = '\0';

            return S_OK;
        }

        if (_wcsicmp(pArgs->szPropertyName, L"PUID") == 0)
        {
            // std::wstringstream stream;
            // stream << std::hex << identity.puid;
            // std::wstring puid(stream.str());

            swprintf(pReturn->szPropertyValue, L"%016X", identity.puid);

            return S_OK;
        }
    }

    {
        identity_token_store_t ps{storage::db_path(), member_name_utf8, true};
        std::wstring value{};

        if (!ps.get(pReturn->szPropertyValue, value))
            return S_FALSE;

        VALIDATE_PARAMETER(value.size() >= 128);
        wcsncpy(pReturn->szPropertyValue, value.c_str(), 128);
        pReturn->szPropertyValue[value.size()] = '\0';

        return S_OK;
    }

    return S_FALSE;
}

IOCTL_FUNC(SetCredential)
{
    VALIDATE_PARAMETER(dwLenIn != sizeof(IOCTL_SET_CREDENTIAL_ARGS));

    auto *pArgs = reinterpret_cast<PIOCTL_SET_CREDENTIAL_ARGS>(pBufIn);
    auto *identityCtx = reinterpret_cast<identity_ctx_t *>(pArgs->hIdentity);
    if (identityCtx == nullptr)
        return E_INVALIDARG;

    auto credentialType = std::wstring(pArgs->szCredentialType);
    auto credentialValue = std::wstring(pArgs->szCredential);

    identityCtx->credentials[credentialType] = credentialValue;

    if (credentialType == L"ps:password" && credentialValue.find_first_not_of('*') == std::wstring::npos)
        identityCtx->use_sts_token = true;

    LOG("SetCredential: hIdentity=0x%08hx; szCredentialType=%s; szCredential=REDACTED;",
        pArgs->hIdentity, util::wstring_to_utf8(credentialType).c_str());

    return S_OK;
}

IOCTL_FUNC(PersistCredential)
{
    VALIDATE_PARAMETER(dwLenIn != sizeof(IOCTL_PERSIST_CREDENTIAL_ARGS));

    auto *pArgs = reinterpret_cast<PIOCTL_PERSIST_CREDENTIAL_ARGS>(pBufIn);
    auto *identityCtx = reinterpret_cast<identity_ctx_t *>(pArgs->hIdentity);
    if (identityCtx == nullptr)
        return E_INVALIDARG;

    auto credentialType = std::wstring(pArgs->szCredType);

    LOG("PersistCredential: hIdentity=0x%08hx; szCredentialType=%s;",
        pArgs->hIdentity, util::wstring_to_utf8(credentialType).c_str());

    auto cred = identityCtx->credentials.find(credentialType);
    if (cred == identityCtx->credentials.end())
        return S_FALSE;

    auto credential = cred->second;

    identity_token_store_t ps{storage::db_path(), util::wstring_to_utf8(identityCtx->member_name)};
    if (!ps.set(credentialType, credential))
        return E_FAIL;

    if (credentialType == L"ps:password")
    {
        if (!ps.set(L"ps:membernameonly", identityCtx->member_name))
            return E_FAIL;
    }

    return S_OK;
}

#define AUTHENTICATED_USING_PASSWORD 0x48803

IOCTL_FUNC(GetAuthStateEx)
{
    VALIDATE_PARAMETER(dwLenIn != sizeof(IOCTL_GET_AUTH_STATE_EX_ARGS));
    VALIDATE_PARAMETER(dwLenOut != sizeof(IOCTL_GET_AUTH_STATE_EX_RETURN));

    auto *pArgs = reinterpret_cast<PIOCTL_GET_AUTH_STATE_EX_ARGS>(pBufIn);
    auto *pReturn = reinterpret_cast<PIOCTL_GET_AUTH_STATE_EX_RETURN>(pBufOut);

    auto *identityCtx = reinterpret_cast<identity_ctx_t *>(pArgs->hIdentity);
    if (identityCtx == nullptr)
        return E_INVALIDARG;

    if (identityCtx->member_name.empty())
        return PPCRL_E_NO_MEMBER_NAME_SET;

    auto len = wcslen(pArgs->szServiceTarget);
    auto target = len != 0 ? std::wstring(pArgs->szServiceTarget) : L"http://Passport.NET/tb";

    token_t token;
    token_store_t ts{storage::db_path()};
    if (ts.retrieve(identityCtx->member_name, target, token))
    {
        pReturn->dwAuthState = AUTHENTICATED_USING_PASSWORD;
        pReturn->dwAuthRequired = 0;
    }
    else
    {
        pReturn->dwAuthState = 0;
        pReturn->dwAuthRequired = 1;
    }

    pReturn->dwRequestStatus = S_OK;
    wcsncpy(pReturn->szWebFlowUrl, L"https://example.com/auth", 512);

    return S_OK;
}

IOCTL_FUNC(AuthIdentityToService)
{
    VALIDATE_PARAMETER(dwLenIn != sizeof(IOCTL_AUTH_IDENTITY_TO_SERVICE_ARGS));
    VALIDATE_PARAMETER(dwLenOut != sizeof(IOCTL_AUTH_IDENTITY_TO_SERVICE_RETURN));

    auto *pArgs = reinterpret_cast<PIOCTL_AUTH_IDENTITY_TO_SERVICE_ARGS>(pBufIn);
    auto *pReturn = reinterpret_cast<PIOCTL_AUTH_IDENTITY_TO_SERVICE_RETURN>(pBufOut);

    auto *identityCtx = reinterpret_cast<identity_ctx_t *>(pArgs->hIdentity);
    if (identityCtx == nullptr)
        return E_INVALIDARG;

    std::wstring service_target{pArgs->szServiceTarget};
    std::wstring service_policy{pArgs->szServicePolicy};

    // this should also fetch creds, but for now i'm going to assume they're cached

    if (pArgs->dwTokenRequestFlags & SERVICE_TOKEN_FROM_CACHE)
    {
        token_t token;
        token_store_t token_store{storage::db_path()};
        if (token_store.retrieve(identityCtx->member_name, service_target, token))
        {
            std::wstring token_wide = util::utf8_to_wstring(token.token);
            VALIDATE_PARAMETER(token_wide.size() >= 1024)

            wcsncpy(pReturn->szToken, token_wide.c_str(), 1024);
            pReturn->szToken[token_wide.size()] = '\0';
            pReturn->dwResultFlags = SERVICE_TOKEN_FROM_CACHE;

            return S_OK;
        }

        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    }

    HRESULT hr;
    // ensuring we have a client configuration, this will kickoff the download and wait for it to complete
    if (FAILED(hr = config::init_client_config()))
    {
        LOG("Failed to initialize client configuration: 0x%08x", hr);
        return hr;
    }

    std::string rst_endpoint;
    {
        config_store_t cs{config::client_config_db_path()};
        rst_endpoint = cs.get(g_endpointRequestSecurityTokens);
        if (rst_endpoint.empty())
        {
            LOG("%s", "RST endpoint is not configured, this should never happen!!");
            return E_UNEXPECTED;
        }
    }

    std::string logon_data_str;
    {
        std::string credentialType = "ps:password";
        std::string credential{};

        identity_token_store_t ps{storage::db_path(), util::wstring_to_utf8(identityCtx->member_name), true};
        if (!ps.get(credentialType, credential))
            return E_FAIL;

        json credentials = {"ps:password", credential};
        json token_requests = json::array();
        token_requests.push_back({
            {"service_target", service_target},
            {"service_policy", service_policy},
        });

        json logon_data = {
            {"identity", util::wstring_to_utf8(identityCtx->member_name)},
            {"credentials", credentials},
            {"token_requests", token_requests}};

        logon_data_str = logon_data.dump();
        return S_OK;
    }

    LOG("AuthIdentityToService data: %s", logon_data_str.c_str());

    std::vector<std::string> additional_headers{};
    if (identityCtx->use_sts_token)
    {
        token_t token;
        token_store_t token_store{storage::db_path()};
        if (token_store.retrieve(identityCtx->member_name, L"http://Passport.NET/tb", token))
            additional_headers.push_back("Authorization: Bearer " + token.token);
    }

    net::client_t client{};
    net::result_t result = client.post(rst_endpoint, logon_data_str, "application/json", additional_headers);
    if (result.curl_error != CURLE_OK)
    {
        return HRESULT_FROM_CURLE(result.curl_error);
    }

    LOG("Received response: %s", result.body.c_str());

    if (result.status_code != 200 && result.status_code != 401)
    {
        LOG("LogonIdentityEx failed with status code %ld", result.status_code);
        return HRESULT_FROM_HTTP(result.status_code);
    }

    if (FAILED(hr = parse_logon_response(identityCtx, result.body)))
    {
        LOG("Failed to parse logon response: 0x%08x", hr);
        return hr;
    }

end:
    return S_OK;
}

IOCTL_FUNC(AuthIdentityToServiceEx)
{
    VALIDATE_PARAMETER(dwLenIn != sizeof(IOCTL_AUTH_IDENTITY_TO_SERVICE_EX_ARGS));

    auto *pArgs = reinterpret_cast<PIOCTL_AUTH_IDENTITY_TO_SERVICE_EX_ARGS>(pBufIn);
    auto *identityCtx = reinterpret_cast<identity_ctx_t *>(pArgs->hIdentity);
    if (identityCtx == nullptr)
        return E_INVALIDARG;

    HRESULT hr;
    // ensuring we have a client configuration, this will kickoff the download and wait for it to complete
    if (FAILED(hr = config::init_client_config()))
    {
        LOG("Failed to initialize client configuration: 0x%08x", hr);
        return hr;
    }

    std::string rst_endpoint;
    {
        config_store_t cs{config::client_config_db_path()};
        rst_endpoint = cs.get(g_endpointRequestSecurityTokens);
        if (rst_endpoint.empty())
        {
            LOG("%s", "RST endpoint is not configured, this should never happen!!");
            return E_UNEXPECTED;
        }
    }

    std::string data;
    if (FAILED(hr = serialise_logon_request(identityCtx, "LEGACY", pArgs->gMapParams, pArgs->dwFileSize, pArgs->dwParamCount, data)))
    {
        LOG("Failed to serialise logon request for identity context 0x%08x", identityCtx);
        return E_FAIL;
    }

    LOG("LogonIdentityEx data: %s", data.c_str());

    std::vector<std::string> additional_headers{};
    if (identityCtx->use_sts_token)
    {
        token_t token;
        token_store_t token_store{storage::db_path()};
        if (token_store.retrieve(identityCtx->member_name, L"http://Passport.NET/tb", token))
            additional_headers.push_back("Authorization: Bearer " + token.token);
    }

    net::client_t client{};
    net::result_t result = client.post(rst_endpoint, data, "application/json", additional_headers);
    if (result.curl_error != CURLE_OK)
    {
        return HRESULT_FROM_CURLE(result.curl_error);
    }

    LOG("Received response: %s", result.body.c_str());

    if (result.status_code != 200 && result.status_code != 401)
    {
        LOG("LogonIdentityEx failed with status code %ld", result.status_code);
        return HRESULT_FROM_HTTP(result.status_code);
    }

    if (FAILED(hr = parse_logon_response(identityCtx, result.body)))
    {
        LOG("Failed to parse logon response: 0x%08x", hr);
        return hr;
    }

    return S_OK;
}

IOCTL_FUNC(LogonIdentityEx)
{
    HRESULT hr = S_OK;
    VALIDATE_PARAMETER(dwLenIn != sizeof(IOCTL_LOGON_IDENTITY_EX_ARGS));

    auto *pArgs = reinterpret_cast<PIOCTL_LOGON_IDENTITY_EX_ARGS>(pBufIn);
    auto *identityCtx = reinterpret_cast<identity_ctx_t *>(pArgs->hIdentity);
    if (identityCtx == nullptr)
        return E_INVALIDARG;

    auto memberName = util::wstring_to_utf8(identityCtx->member_name);
    auto auth_policy = util::wstring_to_utf8(pArgs->szAuthPolicy);
    if (auth_policy.empty())
        auth_policy = "LEGACY";

    LOG("LogonIdentityEx called for identity %s with policy %s",
        memberName.c_str(),
        auth_policy.c_str());

    // ensuring we have a client configuration, this will kickoff the download and wait for it to complete
    if (FAILED(hr = config::init_client_config()))
    {
        LOG("Failed to initialize client configuration: 0x%08x", hr);
        return hr;
    }

    std::string rst_endpoint;
    {
        config_store_t cs{config::client_config_db_path()};
        rst_endpoint = cs.get(g_endpointRequestSecurityTokens);
        if (rst_endpoint.empty())
        {
            LOG("%s", "RST endpoint is not configured, this should never happen!!");
            return E_UNEXPECTED;
        }
    }

    std::string data;
    if (FAILED(hr = serialise_logon_request(identityCtx, auth_policy, pArgs->gMapParams, pArgs->dwFileSize, pArgs->dwParamCount, data)))
    {
        LOG("Failed to serialise logon request for identity %s", memberName.c_str());
        return E_FAIL;
    }

    LOG("LogonIdentityEx data: %s", data.c_str());

    std::vector<std::string> additional_headers{};
    if (identityCtx->use_sts_token)
    {
        token_t token;
        token_store_t token_store{storage::db_path()};
        if (token_store.retrieve(identityCtx->member_name, L"http://Passport.NET/tb", token))
            additional_headers.push_back("Authorization: Bearer " + token.token);
    }

    net::client_t client{};
    net::result_t result = client.post(rst_endpoint, data, "application/json", additional_headers);
    if (result.curl_error != CURLE_OK)
    {
        return HRESULT_FROM_CURLE(result.curl_error);
    }

    LOG("Received response: %s", result.body.c_str());

    if (result.status_code != 200 && result.status_code != 401)
    {
        LOG("LogonIdentityEx failed with status code %ld", result.status_code);
        return HRESULT_FROM_HTTP(result.status_code);
    }

    if (FAILED(hr = parse_logon_response(identityCtx, result.body)))
    {
        LOG("Failed to parse logon response: 0x%08x", hr);
        return hr;
    }

end:
    return S_OK;
}

IOCTL_FUNC(EnumIdentitiesWithCachedCredentials)
{
    VALIDATE_PARAMETER(dwLenIn != sizeof(IOCTL_ENUM_IDENTITIES_WITH_CACHED_CREDENTIALS_ARGS));
    VALIDATE_PARAMETER(dwLenOut != sizeof(IOCTL_ENUM_IDENTITIES_WITH_CACHED_CREDENTIALS_RETURN));

    auto *pArgs = reinterpret_cast<PIOCTL_ENUM_IDENTITIES_WITH_CACHED_CREDENTIALS_ARGS>(pBufIn);
    auto *pReturn = reinterpret_cast<PIOCTL_ENUM_IDENTITIES_WITH_CACHED_CREDENTIALS_RETURN>(pBufOut);

    std::wstring credentialType{pArgs->szCredType};
    std::vector<std::wstring> identities;

    identity_token_store_t ps{storage::db_path(), ""};
    if (!ps.find_identities_for_credential_type(credentialType, identities))
        return E_FAIL;

    if (identities.size() == 0)
    {
        pReturn->hServerHandle = 0;
        pReturn->cbIdentities = 0;
        pReturn->dwIdentities = 0;
        pReturn->gIdentities = {};

        return S_OK;
    }

    DWORD cbSize = 0;
    for (auto &&identity : identities)
    {
        cbSize += (identity.size() + 1) * sizeof(WCHAR);
    }

    GUID guid = {0};
    WCHAR szGuid[40] = {0};
    CoCreateGuid(&guid);
    StringFromGUID2(guid, szGuid, 40);

    HANDLE hMap = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, cbSize, szGuid);
    if (hMap == NULL)
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    BYTE *pMapView = (BYTE *)MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, cbSize);
    if (pMapView == NULL)
    {
        CloseHandle(hMap);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    DWORD dwOffset = 0;
    for (auto &&identity : identities)
    {
        wcscpy((LPWSTR)(pMapView + dwOffset), identity.c_str());
        dwOffset += (identity.size() + 1) * sizeof(WCHAR);
    }

    FlushViewOfFile(pMapView, cbSize);
    UnmapViewOfFile(pMapView);

    pReturn->hServerHandle = (DWORD_PTR)hMap;
    pReturn->cbIdentities = cbSize;
    pReturn->dwIdentities = identities.size();
    pReturn->gIdentities = guid;
    return S_OK;
}

IOCTL_FUNC(CloseEnumIdentitiesHandle)
{
    VALIDATE_PARAMETER(dwLenIn != sizeof(IOCTL_CLOSE_ENUM_IDENTITIES_HANDLE));
    auto *pArgs = reinterpret_cast<PIOCTL_CLOSE_ENUM_IDENTITIES_HANDLE>(pBufIn);

    CloseHandle((HANDLE)pArgs->hServerHandle);

    return S_OK;
}