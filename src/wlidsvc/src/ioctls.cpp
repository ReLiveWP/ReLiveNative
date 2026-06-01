#include <windows.h>
#include <objbase.h>
#include <wlidcomm.h>
#include <wincrypt.h>

#include "ioctls.h"
#include "log.h"
#include "util.h"
#include "globals.h"
#include "microrest.h"
#include "config.h"
#include "urls.h"
#include "storage.h"
#include "deviceid.h"
#include "client.h"
#include "json.h"

#include <algorithm>
#include <base64.hpp>

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

#define PPCRL_REQUEST_E_PASSWORD_EXPIRED 0x80048831
#define PPCRL_REQUEST_E_MISSING_PRIMARY_CREDENTIAL 0x8004882e

#ifndef CERT_SYSTEM_STORE_CURRENT_USER
#define CERT_SYSTEM_STORE_LOCATION_SHIFT 16
#define CERT_SYSTEM_STORE_CURRENT_USER_ID 1
#define CERT_SYSTEM_STORE_CURRENT_USER (CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT)
#endif

HRESULT DeserializeRSTParams(GUID gMapParams, DWORD dwSize, LPBYTE *ppBuffer, RSTParams **ppParams);

HRESULT serialise_logon_request(
    const identity_ctx_t *identityCtx,
    const std::string &auth_policy,
    const GUID &gMapParams,
    const DWORD dwFileSize,
    const DWORD dwParamCount,
    rest::types::security_tokens_request_t &request)
{
    request.identity = util::wstring_to_utf8(identityCtx->member_name);

    HRESULT hr;
    // json credentials = json::object();
    for (auto &&credential : identityCtx->credentials)
    {
        request.credentials.insert({util::wstring_to_utf8(credential.first), util::wstring_to_utf8(credential.second)});
    }

    if (request.credentials.size() == 0)
    {
        if (identityCtx->use_sts_token)
        {
            token_t token;
            token_store_t token_store{storage::db_path()};
            if (!token_store.retrieve(identityCtx->member_name, L"http://Passport.NET/tb", token) || !token.is_valid())
            {
                LOG("No credentials set for identity %s, attempted to use Passport.NET, it doesn't exist or is invalid.", util::wstring_to_utf8(identityCtx->member_name).c_str());
                return PPCRL_REQUEST_E_MISSING_PRIMARY_CREDENTIAL;
            }
        }
        else
        {
            LOG("No credentials set for identity %s", util::wstring_to_utf8(identityCtx->member_name).c_str());
            return PPCRL_REQUEST_E_MISSING_PRIMARY_CREDENTIAL;
        }
    }

    // json token_requests = json::array();

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
        request.token_requests.push_back({util::wstring_to_utf8(param->szServiceTarget),
                                          util::wstring_to_utf8(param->szServicePolicy)});
    }

    delete[] pBuffer;

    // the global token is important, make sure we always request one
    request.token_requests.push_back({"http://Passport.NET/tb", auth_policy});

    return S_OK;
}

HRESULT store_security_tokens(identity_ctx_t *identityCtx, const rest::types::security_tokens_response_t &response)
{
    const auto &username = response.username;

    {
        identity_store_t identity_store{storage::db_path()};

        identity_t identity;
        identity.identity = util::wstring_to_utf8(identityCtx->member_name);
        identity.puid = response.puid;
        identity.cid = response.cid;
        identity.email = response.email_address;
        identity.display_name = username;

        if (!identity_store.store(identity))
            return E_FAIL;
    }

    {
        token_store_t token_store{storage::db_path()};
        for (const auto &sec_token : response.security_tokens)
        {
            token_t t = sec_token.to_token(util::wstring_to_utf8(identityCtx->member_name));
            if (!token_store.store(t))
                continue;
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

    // Ensure NUL-terminated within the supplied buffer before passing to LOG.
    std::string msg(reinterpret_cast<const char *>(pBufIn), dwLenIn);
    LOG("LOGMSG [0x%08x] %s", hContext, msg.c_str());

    return S_OK;
}

IOCTL_FUNC(HandleLogMessageWide)
{
    if (pBufIn == NULL || dwLenIn == 0)
        return E_INVALIDARG;

    // Limit to the supplied byte count so we never walk off the end of the buffer.
    size_t wcharCount = dwLenIn / sizeof(wchar_t);
    std::wstring wmsg(reinterpret_cast<const wchar_t *>(pBufIn), wcharCount);
    const char *tmp = wchar_to_char(wmsg.c_str());
    if (tmp == nullptr)
        return E_OUTOFMEMORY;

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
        LOG("[0x%08x] %s", hContext, "API version mismatch detected! This should never happen!!");
        return E_UNEXPECTED;
    }

    std::memcpy(&hContext->app, &pArgs->gApp, sizeof(GUID));
    hContext->major_version = pArgs->dwMajorVersion;
    hContext->minor_version = pArgs->dwMinorVersion;
    hContext->exec_path = std::wstring(pArgs->szExecutable, wcslen(pArgs->szExecutable));

    WCHAR lpGuid[40] = {0};
    StringFromGUID2(pArgs->gApp, lpGuid, 40);

    auto exec_path = util::wstring_to_utf8(hContext->exec_path);
    hContext->app_guid = std::wstring(lpGuid);

    auto guid = util::wstring_to_utf8(hContext->app_guid);
    LOG("[0x%08x] Initialized app %s, dwMajor: %d, dwMinor: %d, execPath: %s",
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

    wcsncpy(data.szDefaultId, default_id.c_str(), 255);
    data.szDefaultId[255] = L'\0';

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

    // Bound the member name to the declared field size before constructing.
    std::wstring memberName(pArgs->szMemberName, wcslen(pArgs->szMemberName));
    auto *identityCtx = new (std::nothrow) identity_ctx_t(hContext, memberName.c_str(), pArgs->dwIdentityFlags);
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

    // Only delete a pointer we own — reject arbitrary userspace addresses.
    auto it = std::find(identities.begin(), identities.end(), identity);
    if (it == identities.end())
        return E_INVALIDARG;

    identities.erase(it);
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

    LOG("looking up identity property for member %s", member_name_utf8.c_str());

    {
        identity_t identity;
        identity_store_t id_store{storage::db_path()};

        if (!id_store.retrieve(member_name_utf8, identity))
        {
            LOG("member %s not found?? trying default name", member_name_utf8.c_str());

            member_name_utf8 = util::wstring_to_utf8(config::default_id());
            if (!id_store.retrieve(member_name_utf8, identity))
            {
                LOG("default member %s not found?? c'est buggered!!", member_name_utf8.c_str());
                return E_UNEXPECTED;
            }

            // we probably dont want this
            identityCtx->member_name = config::default_id();
        }

        if (_wcsicmp(pArgs->szPropertyName, L"MemberName") == 0)
        {
            std::wstring member_name = util::utf8_to_wstring(identity.identity);

            VALIDATE_PARAMETER(member_name.size() >= 128);
            wcsncpy(pReturn->szPropertyValue, member_name.c_str(), 127);
            pReturn->szPropertyValue[127] = L'\0';

            return S_OK;
        }

        if (_wcsicmp(pArgs->szPropertyName, L"CID") == 0)
        {
            std::wstring cuid = util::utf8_to_wstring(identity.cid);

            VALIDATE_PARAMETER(cuid.size() >= 128);
            wcsncpy(pReturn->szPropertyValue, cuid.c_str(), 127);
            pReturn->szPropertyValue[127] = L'\0';

            return S_OK;
        }

        if (_wcsicmp(pArgs->szPropertyName, L"PUID") == 0)
        {
            // std::wstringstream stream;
            // stream << std::hex << identity.puid;
            // std::wstring puid(stream.str());

            swprintf(pReturn->szPropertyValue, L"%I64X", identity.puid);

            return S_OK;
        }
    }

    {
        identity_token_store_t ps{storage::db_path(), member_name_utf8, true};
        std::wstring value{};
        std::wstring propName(pArgs->szPropertyName, wcslen(pArgs->szPropertyName));

        if (!ps.get(propName, value))
            return S_FALSE;

        VALIDATE_PARAMETER(value.size() >= 128);
        wcsncpy(pReturn->szPropertyValue, value.c_str(), 127);
        pReturn->szPropertyValue[127] = L'\0';

        return S_OK;
    }

    return S_FALSE;
}

IOCTL_FUNC(SetIdentityProperty)
{
    VALIDATE_PARAMETER(dwLenIn != sizeof(IOCTL_SET_IDENTITY_PROPERTY_ARGS));

    auto *pArgs = reinterpret_cast<PIOCTL_SET_IDENTITY_PROPERTY_ARGS>(pBufIn);
    auto *identityCtx = reinterpret_cast<identity_ctx_t *>(pArgs->hIdentity);
    if (identityCtx == nullptr)
        return E_INVALIDARG;

    auto property = std::wstring(pArgs->szProperty);
    LOG("SetIdentityProperty: hIdentity=0x%08hx; dwProperty=%d; szProperty=%s;",
        pArgs->hIdentity, pArgs->dwProperty, util::wstring_to_utf8(property).c_str());

    switch (pArgs->dwProperty)
    {
    case 1: // IDENTITY_MEMBER_NAME
        identityCtx->member_name = property;
        break;
    }

    return S_OK;
}

IOCTL_FUNC(SetCredential)
{
    VALIDATE_PARAMETER(dwLenIn != sizeof(IOCTL_SET_CREDENTIAL_ARGS));

    auto *pArgs = reinterpret_cast<PIOCTL_SET_CREDENTIAL_ARGS>(pBufIn);
    auto *identityCtx = reinterpret_cast<identity_ctx_t *>(pArgs->hIdentity);
    if (identityCtx == nullptr)
        return E_INVALIDARG;

    auto is_asterisks = [](std::wstring &str) -> bool
    {
        for (auto c : str)
        {
            if (c != L'*')
                return false;
        }

        return true;
    };

    auto credentialType = std::wstring(pArgs->szCredentialType);
    auto credentialValue = std::wstring(pArgs->szCredential);

    if (credentialValue.length() > 0 && !is_asterisks(credentialValue))
    {
        identityCtx->use_sts_token = false;
        identityCtx->credentials[credentialType] = credentialValue;
    }
    else
    {
        identity_token_store_t ps{storage::db_path(), util::wstring_to_utf8(identityCtx->member_name)};
        if (ps.get(credentialType, credentialValue))
        {
            identityCtx->use_sts_token = false;
            identityCtx->credentials[credentialType] = credentialValue;
        }
    }

    LOG("SetCredential: hIdentity=0x%08hx; szCredentialType=%s; szCredential=%s;",
        pArgs->hIdentity, util::wstring_to_utf8(credentialType).c_str(), util::wstring_to_utf8(credentialValue).c_str());

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

#define PPCRL_AUTHSTATE_S_AUTHENTICATED_PASSWORD 0x48803
#define PPCRL_AUTHSTATE_E_EXPIRED 0x80048801

#define PPCRL_E_UNABLE_TO_RETRIEVE_SERVICE_TOKEN 0x80048862

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
        if (!token.is_valid())
        {
            pReturn->dwAuthState = PPCRL_AUTHSTATE_E_EXPIRED;
            pReturn->dwAuthRequired = 0x00048808;
            pReturn->dwRequestStatus = PPCRL_E_UNABLE_TO_RETRIEVE_SERVICE_TOKEN;
        }

        pReturn->dwAuthState = PPCRL_AUTHSTATE_S_AUTHENTICATED_PASSWORD;
        pReturn->dwAuthRequired = 0;
        pReturn->dwRequestStatus = S_OK;
    }
    else
    {
        pReturn->dwAuthState = PPCRL_AUTHSTATE_S_AUTHENTICATED_PASSWORD;
        pReturn->dwAuthRequired = 0x00048808;
        pReturn->dwRequestStatus = PPCRL_E_UNABLE_TO_RETRIEVE_SERVICE_TOKEN;
    }

    // wcsncpy(pReturn->szWebFlowUrl, L"https://example.com/auth", 512);
    wcsncpy(pReturn->szWebFlowUrl, L"", 512);

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
        if (token_store.retrieve(identityCtx->member_name, service_target, token) && token.is_valid())
        {
            std::wstring token_wide = util::utf8_to_wstring(token.token);
            VALIDATE_PARAMETER(token_wide.size() >= 4096)

            wcsncpy(pReturn->szToken, token_wide.c_str(), 4095);
            pReturn->szToken[4095] = L'\0';
            pReturn->dwResultFlags = SERVICE_TOKEN_FROM_CACHE;

            return S_OK;
        }

        return PPCRL_REQUEST_E_PASSWORD_EXPIRED;
    }

    rest::types::security_tokens_request_t request{
        .identity = util::wstring_to_utf8(identityCtx->member_name)};

    for (auto &&credential : identityCtx->credentials)
        request.credentials.insert({util::wstring_to_utf8(credential.first), util::wstring_to_utf8(credential.second)});

    request.token_requests.push_back({util::wstring_to_utf8(service_target),
                                      util::wstring_to_utf8(service_policy)});

    rest::types::security_tokens_response_t response{};

    rest::reliveid_client_t client{identityCtx};
    rest::error_t error = client.request_security_tokens(request, response);
    if (error.failed())
    {
        LOG("request_security_tokens failed 0x%08x", error.hr);
        return error.hr;
    }

    HRESULT hr;
    if (FAILED(hr = store_security_tokens(identityCtx, response)))
    {
        LOG("store_security_tokens failed 0x%08x", error.hr);
        return hr;
    }

    auto &token = response.security_tokens[0];
    std::wstring token_wide = util::utf8_to_wstring(token.token);
    wcsncpy(pReturn->szToken, token_wide.c_str(), 4095);
    pReturn->szToken[4095] = L'\0';

    return S_OK;
}

IOCTL_FUNC(AuthIdentityToServiceEx)
{
    VALIDATE_PARAMETER(dwLenIn != sizeof(IOCTL_AUTH_IDENTITY_TO_SERVICE_EX_ARGS));

    auto *pArgs = reinterpret_cast<PIOCTL_AUTH_IDENTITY_TO_SERVICE_EX_ARGS>(pBufIn);
    auto *identityCtx = reinterpret_cast<identity_ctx_t *>(pArgs->hIdentity);
    if (identityCtx == nullptr)
        return E_INVALIDARG;

    rest::types::security_tokens_request_t request{};
    rest::types::security_tokens_response_t response{};

    HRESULT hr;
    if (FAILED(hr = serialise_logon_request(identityCtx, "LEGACY", pArgs->gMapParams, pArgs->dwFileSize, pArgs->dwParamCount, request)))
    {
        LOG("Failed to serialise logon request for identity context 0x%08x", identityCtx);
        return hr;
    }

    rest::reliveid_client_t client{identityCtx};
    rest::error_t error = client.request_security_tokens(request, response);
    if (error.failed())
    {
        LOG("request_security_tokens failed 0x%08x", error.hr);
        return error.hr;
    }

    return store_security_tokens(identityCtx, response);
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

    rest::types::security_tokens_request_t request{};
    rest::types::security_tokens_response_t response{};

    if (FAILED(hr = serialise_logon_request(identityCtx, auth_policy, pArgs->gMapParams, pArgs->dwFileSize, pArgs->dwParamCount, request)))
    {
        LOG("Failed to serialise logon request for identity %s", memberName.c_str());
        return E_FAIL;
    }

    if (identityCtx->use_sts_token)
    {
        token_t token{};
        token_store_t token_store{storage::db_path()};
        if (!token_store.retrieve(identityCtx->member_name, L"http://Passport.NET/tb", token) || !token.is_valid())
            return PPCRL_REQUEST_E_MISSING_PRIMARY_CREDENTIAL;
    }

    rest::reliveid_client_t client{identityCtx};
    rest::error_t error = client.request_security_tokens(request, response);
    if (error.failed())
    {
        LOG("request_security_tokens failed 0x%08x", error.hr);
        return error.hr;
    }

    return store_security_tokens(identityCtx, response);
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

    // Accumulate in 64-bit to detect overflow before truncating to DWORD.
    uint64_t cbSize64 = 0;
    for (auto &&identity : identities)
        cbSize64 += (uint64_t)(identity.size() + 1) * sizeof(WCHAR);

    if (cbSize64 > 16 * 1024 * 1024) // 16 MB sanity cap
        return HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW);

    DWORD cbSize = (DWORD)cbSize64;

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
        DWORD entryBytes = (DWORD)(identity.size() + 1) * sizeof(WCHAR);
        if ((uint64_t)dwOffset + entryBytes > cbSize)
            break; // should never happen given the pre-calculated size
        wcscpy((LPWSTR)(pMapView + dwOffset), identity.c_str());
        dwOffset += entryBytes;
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

IOCTL_FUNC(GetDeviceId)
{
    VALIDATE_PARAMETER(dwLenIn != sizeof(IOCTL_GET_DEVICE_ID_ARGS));
    VALIDATE_PARAMETER(dwLenOut != sizeof(IOCTL_GET_DEVICE_ID_RETURN));

    auto *pArgs = reinterpret_cast<PIOCTL_GET_DEVICE_ID_ARGS>(pBufIn);
    auto *pReturn = reinterpret_cast<PIOCTL_GET_DEVICE_ID_RETURN>(pBufOut);

    HRESULT hr;

    {
        config_store_t ct{storage::db_path()};
        std::wstring str = ct.get(L"DeviceDefaultID_v1");
        if (str.empty())
        {
            // TODO: i do not know if this is necessary but we're going to do the provisioning now
            if (FAILED(hr = wlidsvc::deviceid::EnsureProvisionedAsync()))
            {
                return hr;
            }

            str = ct.get(L"DeviceDefaultID_v1");
        }

        wcsncpy(pReturn->szDeviceId, str.data(), 128);
    }

    if (pArgs->bNeedsCert)
    {
        std::string device_cert_thumb;
        if (FAILED(hr = wlidsvc::deviceid::FindDeviceCert(TRUE, device_cert_thumb)))
        {
            return hr;
        }

        std::string raw_thumbprint = base64::from_base64(device_cert_thumb);
        if (raw_thumbprint.size() < 20)
            return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        memcpy(pReturn->bDeviceCertThumb, raw_thumbprint.c_str(), 20);
    }

    return S_OK;
}

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

    // Validate the caller-supplied size against the actual mapping size.
    if (dwSize < sizeof(DWORD) * 2)
    {
        UnmapViewOfFile(pMapView);
        CloseHandle(hMap);
        return E_INVALIDARG;
    }

    DWORD cbSize = *(DWORD *)pMapView;
    if (cbSize > dwSize || cbSize < sizeof(DWORD) * 2)
    {
        UnmapViewOfFile(pMapView);
        CloseHandle(hMap);
        return E_INVALIDARG;
    }

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
    DWORD dwParamCount = *(DWORD *)(pBuffer + 4);

    // Validate that the declared params fit within the buffer.
    if (dwParamCount > (cbSize - 8) / sizeof(RSTParams))
    {
        delete[] pBuffer;
        return E_INVALIDARG;
    }

    RSTParams *pParams = reinterpret_cast<RSTParams *>(pBuffer + 8);
    for (int i = 0; i < (int)dwParamCount; ++i)
    {
        // fixup the pointers in the RSTParams structure, validating offsets
        RSTParams *pParam = &pParams[i];
        if (pParam->szServiceTarget != nullptr)
        {
            DWORD_PTR offset = (DWORD_PTR)pParam->szServiceTarget;
            if (offset < 8 || offset >= cbSize)
            {
                delete[] pBuffer;
                return E_INVALIDARG;
            }
            pParam->szServiceTarget = reinterpret_cast<LPWSTR>(pBuffer + offset);
        }
        if (pParam->szServicePolicy != nullptr)
        {
            DWORD_PTR offset = (DWORD_PTR)pParam->szServicePolicy;
            if (offset < 8 || offset >= cbSize)
            {
                delete[] pBuffer;
                return E_INVALIDARG;
            }
            pParam->szServicePolicy = reinterpret_cast<LPWSTR>(pBuffer + offset);
        }

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
