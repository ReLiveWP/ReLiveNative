#include <windows.h>
#include <wlidcomm.h>
#include "ioctls.h"
#include "log.h"
#include "util.h"
#include "globals.h"

#include <algorithm>

using namespace wlidsvc;

IOCTL_FUNC(HandleLogMessage)
{
    if (pBufIn == NULL || dwLenIn == 0)
        return E_INVALIDARG;

    LOG("[%08x] %s", hContext, pBufIn);

    return S_OK;
}

IOCTL_FUNC(HandleLogMessageWide)
{
    if (pBufIn == NULL || dwLenIn == 0)
        return E_INVALIDARG;

    const char *tmp = wchar_to_char((const wchar_t *)pBufIn);

    LOG_WIDE(L"[%08x] %s", hContext, tmp);

    delete[] tmp;

    return S_OK;
}

IOCTL_FUNC(InitHandle)
{
    HRESULT hr;
    util::impersonate_t impersonate{};

    if (pBufIn == NULL || dwLenIn == 0)
        return E_INVALIDARG;
    VALIDATE_PARAMETER(dwLenIn != sizeof(IOCTL_INIT_HANDLE_ARGS));

    if (FAILED(hr = impersonate.verify_policy()))
    {
        LOG("verify_policy() failed: 0x%08x;", hr);
        return hr;
    }

    if (FAILED(hr = impersonate.impersonate()))
    {
        LOG("impersonate() failed: 0x%08x;", hr);
        return hr;
    }

    auto *pArgs = reinterpret_cast<PIOCTL_INIT_HANDLE_ARGS>(pBufIn);

    std::memcpy(&hContext->app, &pArgs->gApp, sizeof(GUID));
    hContext->major_version = pArgs->dwMajorVersion;
    hContext->minor_version = pArgs->dwMinorVersion;
    hContext->exec_path = {pArgs->szExecutable};

    return S_OK;
}

IOCTL_FUNC(GetDefaultID)
{
    HRESULT hr = S_OK;
    IOCTL_GET_DEFAULT_ID_RETURN data{};
    util::impersonate_t impersonate{};
    if (FAILED(hr = impersonate.verify_policy(L"WLIDSVCCAPUSERAPI")))
    {
        LOG("verify_policy() failed: 0x%08x;", hr);
        return hr;
    }

    if (FAILED(hr = impersonate.impersonate()))
    {
        LOG("impersonate() failed: 0x%08x;", hr);
        return hr;
    }

    VALIDATE_PARAMETER(dwLenOut != sizeof(IOCTL_GET_DEFAULT_ID_RETURN));

    // TODO: this is 1:1 with the original code, not convinced this is what we want to be doing strictly speaking
    util::hkey_t hKey;
    DWORD disposition;
    LONG status = RegCreateKeyEx(HKEY_CURRENT_USER, TEXT("Software\\Microsoft\\IdentityCRL\\Environment\\Production"), 0, NULL, 0, 0x2001, NULL, hKey.put(), &disposition);
    if (status != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(status);

    DWORD dwLen;
    status = RegQueryValueEx(hKey.get(), TEXT("DefaultID"), NULL, &disposition, NULL, &dwLen);
    if (status != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(status);

    VALIDATE_PARAMETER(dwLen < 256);

    status = RegQueryValueEx(hKey.get(), TEXT("DefaultID"), NULL, &disposition, (LPBYTE)data.szDefaultId, &dwLen);
    if (status != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(status);

    data.szDefaultId[dwLen] = L'\0';

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

    auto *identityCtx = new (std::nothrow) identity_ctx_t(pArgs->szMemberName, pArgs->dwIdentityFlags);
    if (identityCtx == nullptr)
        return E_OUTOFMEMORY;

    pReturn->hIdentity = (DWORD_PTR)identityCtx;
    hContext->associated_identities.push_back(identityCtx);

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