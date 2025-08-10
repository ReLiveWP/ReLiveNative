#include <windows.h>
#include <objbase.h>
#include <wlidcomm.h>
#include "ioctls.h"
#include "log.h"
#include "util.h"
#include "globals.h"
#include "storage.h"
#include "microrest.h"
#include "config.h"
#include "urls.h"

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

HRESULT DeserializeRSTParams(GUID gMapParams, LPBYTE *ppBuffer, RSTParams **ppParams)
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

    HANDLE hMap = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0, szGuid);
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

    VALIDATE_PARAMETER(default_id.size() < 256);

    wcscpy(data.szDefaultId, default_id.c_str());

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

    const auto &properties = identityCtx->properties;
    const std::wstring propertyName(pArgs->szPropertyName);
    auto it = properties.find(propertyName);
    if (it != properties.end())
    {
        const auto &propertyValue = it->second;
        if (propertyValue.size() >= 128)
        {
            LOG("Property value for '%s' is too long: %d characters, max is 127.",
                util::wstring_to_utf8(propertyName).c_str(), propertyValue.size());
            return E_INVALIDARG;
        }

        wcscpy(pReturn->szPropertyValue, propertyValue.c_str());
        return S_OK;
    }

    if (_wcsicmp(pArgs->szPropertyName, L"MemberName") == 0)
    {
        // this seems wroooong? but it's expected by wlidux.dll#AsyncLogonIdentityExWithUI
        if (identityCtx->member_name.empty())
            return PPCRL_E_NO_MEMBER_NAME_SET;

        if (identityCtx->member_name.size() >= 128)
        {
            LOG("MemberName is too long: %d characters, max is 127.", identityCtx->member_name.size());
            return E_INVALIDARG;
        }

        wcscpy(pReturn->szPropertyValue, identityCtx->member_name.c_str());
        return S_OK;
    }
    else
    {
        return S_FALSE;
    }
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

    LOG("SetCredential: hIdentity=%08hx; szCredentialType=%s; szCredential=%s;",
        pArgs->hIdentity, util::wstring_to_utf8(credentialType).c_str(), util::wstring_to_utf8(credentialValue).c_str());

    // dump the properties for debugging
    LOG("Credentials for identity %s:", util::wstring_to_utf8(identityCtx->member_name).c_str());
    for (const auto &prop : identityCtx->credentials)
    {
        LOG("  %s: %s", util::wstring_to_utf8(prop.first).c_str(),
            util::wstring_to_utf8(prop.second).c_str());
    }

    return S_OK;
}

IOCTL_FUNC(GetAuthStateEx)
{
    VALIDATE_PARAMETER(dwLenIn != sizeof(IOCTL_GET_AUTH_STATE_EX_ARGS));
    VALIDATE_PARAMETER(dwLenOut != sizeof(IOCTL_GET_AUTH_STATE_EX_RETURN));

    auto *pArgs = reinterpret_cast<PIOCTL_GET_AUTH_STATE_EX_ARGS>(pBufIn);
    auto *pReturn = reinterpret_cast<PIOCTL_GET_AUTH_STATE_EX_RETURN>(pBufOut);

    auto *identityCtx = reinterpret_cast<identity_ctx_t *>(pArgs->hIdentity);
    if (identityCtx == nullptr)
        return E_INVALIDARG;

    pReturn->dwAuthState = 0;
    pReturn->dwAuthRequired = 1;
    pReturn->dwRequestStatus = S_OK;
    wcscpy(pReturn->szWebFlowUrl, L"https://example.com/auth");

    return S_OK;
}

IOCTL_FUNC(AuthIdentityToServiceEx)
{
    VALIDATE_PARAMETER(dwLenIn != sizeof(IOCTL_AUTH_IDENTITY_TO_SERVICE_EX_ARGS));

    auto *pArgs = reinterpret_cast<PIOCTL_AUTH_IDENTITY_TO_SERVICE_EX_ARGS>(pBufIn);
    auto *identityCtx = reinterpret_cast<identity_ctx_t *>(pArgs->hIdentity);
    if (identityCtx == nullptr)
        return E_INVALIDARG;

    HRESULT hr = S_OK;
    LPBYTE pBuffer = nullptr;
    RSTParams *pParams = nullptr;
    if (FAILED(hr = DeserializeRSTParams(pArgs->gMapParams, &pBuffer, &pParams)))
    {
        LOG("DeserializeRSTParams failed: 0x%08x", hr);
        return hr;
    }

    delete[] pBuffer;
    return E_NOTIMPL;
}

IOCTL_FUNC(LogonIdentityEx)
{
    HRESULT hr = S_OK;
    VALIDATE_PARAMETER(dwLenIn != sizeof(IOCTL_LOGON_IDENTITY_EX_ARGS));

    auto *pArgs = reinterpret_cast<PIOCTL_LOGON_IDENTITY_EX_ARGS>(pBufIn);
    auto *identityCtx = reinterpret_cast<identity_ctx_t *>(pArgs->hIdentity);
    if (identityCtx == nullptr)
        return E_INVALIDARG;

    LOG("LogonIdentityEx called for identity %s with policy %s",
        util::wstring_to_utf8(identityCtx->member_name).c_str(),
        util::wstring_to_utf8(pArgs->szAuthPolicy).c_str());

    // ensuring we have a client configuration, this will kickoff the download and wait for it to complete
    if (FAILED(hr = config::init_client_config()))
    {
        LOG("Failed to initialize client configuration: 0x%08x", hr);
        return hr;
    }

    config_store_t cs{config::client_config_db_path()};
    auto rst_endpoint = cs.get(g_endpointRequestSecurityTokens);
    if (rst_endpoint.empty())
    {
        LOG("%s", "RST endpoint is not configured, this should never happen!!");
        return E_UNEXPECTED;
    }

    auto auth_policy = util::wstring_to_utf8(pArgs->szAuthPolicy);
    if (auth_policy.empty())
        auth_policy = "LEGACY";

    json credentials = json::object();
    for (auto &&credential : identityCtx->credentials)
    {
        credentials[util::wstring_to_utf8(credential.first)] = util::wstring_to_utf8(credential.second);
    }

    if (credentials.size() == 0)
    {
        LOG("No credentials set for identity %s", util::wstring_to_utf8(identityCtx->member_name).c_str());
        return PPCRL_REQUEST_E_MISSING_PRIMARY_CREDENTIAL;
    }

    json token_requests = json::array();
    token_requests.push_back({
        {"service_target", "http://Passport.NET/tb"},
        {"service_policy", auth_policy},
    });

    LPBYTE pBuffer = nullptr;
    RSTParams *pParams = nullptr;
    if (FAILED(hr = DeserializeRSTParams(pArgs->gMapParams, &pBuffer, &pParams)))
    {
        LOG("DeserializeRSTParams failed: 0x%08x", hr);
        return hr;
    }

    for (DWORD i = 0; i < pArgs->dwParamCount; ++i)
    {
        RSTParams *param = &pParams[i];
        json token_request = {
            {"service_target", util::wstring_to_utf8(param->szServiceTarget)},
            {"service_policy", util::wstring_to_utf8(param->szServicePolicy)}};

        token_requests.push_back(token_request);
    }

    delete[] pBuffer;

    json logon_data = {
        {"identity", util::wstring_to_utf8(identityCtx->member_name)},
        {"credentials", credentials},
        {"token_requests", token_requests}};

    std::string data = logon_data.dump();
    LOG("LogonIdentityEx data: %s", data.c_str());

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

    net::client_t client{};
    net::result_t result = client.post(rst_endpoint, data, "application/json");
    if (result.curl_error != CURLE_OK)
    {
        return CURLE_TO_HRESULT(result.curl_error);
    }

    auto response = json::parse(result.body, nullptr, false);
    if (response.is_discarded())
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    }

    const auto username = response["username"].get<std::string>();

    {
        identity_store_t identity_store{storage::db_path()};

        identity_t identity;
        identity.identity = username;
        identity.puid = response["puid"].get<uint64_t>();
        identity.cuid = response["cid"].get<std::string>();
        identity.email = response["email_address"].get<std::string>();
        identity.display_name = username;

        identity_store.store(identity);
        LOG("Stored identity: %s (PUID: %llu, CUID: %s, Email: %s)",
            identity.identity.c_str(),
            identity.puid,
            identity.cuid.c_str(),
            identity.email.c_str());
    }

    {
        token_store_t token_store{storage::db_path()};

        for (const auto &token : response["security_tokens"])
        {
            token_t t;
            t.identity = username;
            t.service = token["service_target"].get<std::string>();
            t.token = token["token"].get<std::string>();
            t.type = "JWT";
            t.expires = token["expires"].get<std::string>();
            t.created = token["created"].get<std::string>();

            token_store.store(t);
            LOG("Stored token for %s: %s (Type: %s, Expires: %s)",
                username.c_str(),
                t.service.c_str(),
                t.type.c_str(),
                t.expires.c_str());
        }
    }

end:
    return hr;
}