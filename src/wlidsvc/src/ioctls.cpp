#include <windows.h>
#include <objbase.h>
#include <wlidcomm.h>
#include "ioctls.h"
#include "log.h"
#include "util.h"
#include "globals.h"
#include "microrest.h"
#include "config.h"

#include <algorithm>

#include <cerrno>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

using namespace wlidsvc;
using namespace wlidsvc::net;

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

    if (_wcsicmp(pArgs->szPropertyName, L"MemberName") == 0)
    {
        return PPCRL_E_NO_MEMBER_NAME_SET;
    }
    else
    {
        return E_NOTIMPL;
    }
}