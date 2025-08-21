#include <windows.h>
#include <windows.h>
#include "msidcrl.h"
#include <stdio.h>
#include <stdlib.h>
#include <ncrypt.h>

#ifdef UNDER_CE
#define wWinMain WinMain
#undef GetProcAddress
#define GetProcAddress(hInst, x) GetProcAddressW(hInst, TEXT(x))
#endif

#ifndef CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG
#define CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG 0x40000
#endif

typedef void (*TEST_InitHooks)(void);
typedef HRESULT (*msidcrl_Initialize)(GUID *lpGuid, DWORD dwVersionMajor, DWORD dwVersionMinor);
typedef HRESULT (*msidcrl_Uninitialize)(void);

typedef HRESULT (*msidcrl_CreateIdentityHandle)(LPCWSTR szMemberName, DWORD dwIdentityFlags, HIDENTITY *phIdentity);
typedef HRESULT (*msidcrl_CloseIdentityHandle)(HIDENTITY hIdentity);

typedef HRESULT (*msidcrl_SetCredential)(HIDENTITY hIdentity, LPCWSTR szCredentialType, LPCWSTR szCredentialValue);
typedef HRESULT (*msidcrl_LogonIdentityEx)(HIDENTITY hIdentity, LPCWSTR szAuthPolicy, DWORD dwAuthFlags, RSTParams *pcRSTParams, DWORD dwpcRSTParamsCount);

typedef HRESULT (*msidcrl_GetDeviceId)(
    IN DWORD dwFlags,
    IN LPCWSTR pvAdditionalParams,
    OUT LPWSTR *pwszDeviceId,
    OUT PCCERT_CONTEXT *didCertContext);

#ifdef UNDER_CE
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nShowCmd)
#else
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
#endif
{
    GUID gidReference;
    HRESULT hCreateGuid = CoCreateGuid(&gidReference);

    HMODULE hMsidcrl = LoadLibrary(TEXT("msidcrl40"));
    msidcrl_Initialize Initialize = (msidcrl_Initialize)GetProcAddress(hMsidcrl, "Initialize");
    msidcrl_CreateIdentityHandle CreateIdentityHandle = (msidcrl_CreateIdentityHandle)GetProcAddress(hMsidcrl, "CreateIdentityHandle");
    msidcrl_CloseIdentityHandle CloseIdentityHandle = (msidcrl_CloseIdentityHandle)GetProcAddress(hMsidcrl, "CloseIdentityHandle");
    msidcrl_LogonIdentityEx LogonIdentityEx = (msidcrl_LogonIdentityEx)GetProcAddress(hMsidcrl, "LogonIdentityEx");
    msidcrl_SetCredential SetCredential = (msidcrl_SetCredential)GetProcAddress(hMsidcrl, "SetCredential");
    msidcrl_Uninitialize Uninitialize = (msidcrl_Uninitialize)GetProcAddress(hMsidcrl, "Uninitialize");
    msidcrl_GetDeviceId GetDeviceId = (msidcrl_GetDeviceId)GetProcAddress(hMsidcrl, "GetDeviceId");

    Initialize(&gidReference, 1, 0);

    HIDENTITY hIdentity = nullptr;
    HRESULT hr = CreateIdentityHandle(TEXT("test@test.com"), 0, &hIdentity);
    if (FAILED(hr))
    {
        MessageBox(NULL, TEXT("Failed to create identity handle"), TEXT("Error"), MB_OK | MB_ICONERROR);
        return -1;
    }

    hr = SetCredential(hIdentity, TEXT("ps:password"), TEXT("asdf"));
    if (FAILED(hr))
    {
        // dont bother to clean up, just exit
        MessageBox(NULL, TEXT("Failed to set credential"), TEXT("Error"), MB_OK | MB_ICONERROR);
        CloseIdentityHandle(hIdentity);
        return -1;
    }

    RSTParams params = {sizeof(RSTParams), TEXT("login.live.com"), TEXT("MBI_KEY"), 0, 0};
    hr = LogonIdentityEx(hIdentity, nullptr, 0, &params, 1);
    if (FAILED(hr))
    {
        MessageBox(NULL, TEXT("Failed to logon identity"), TEXT("Error"), MB_OK | MB_ICONERROR);
        CloseIdentityHandle(hIdentity);
        return -1;
    }

    LPWSTR deviceId;
    PCCERT_CONTEXT ctx;
    hr = GetDeviceId(0, NULL, &deviceId, &ctx);
    if (FAILED(hr))
    {
        MessageBox(NULL, TEXT("Failed to get device ID"), TEXT("Error"), MB_OK | MB_ICONERROR);
        return -1;
    }

    NCRYPT_KEY_HANDLE handle = 0;
    DWORD keySpec;
    BOOL fCallerFreeProvOrNCryptKey;
    BOOL ret = CryptAcquireCertificatePrivateKey(ctx, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, NULL, &handle, &keySpec, &fCallerFreeProvOrNCryptKey);
    if (ret == FALSE)
    {
        WCHAR fuck[64]{0};
        _snwprintf(fuck, 64, L"%d", GetLastError());
        MessageBox(NULL, fuck, TEXT("Error"), MB_OK | MB_ICONERROR);
        return GetLastError();
    }

    hr = CloseIdentityHandle(hIdentity);
    if (FAILED(hr))
    {
        MessageBox(NULL, TEXT("Failed to close identity handle"), TEXT("Error"), MB_OK | MB_ICONERROR);
        return -1;
    }

    MessageBox(NULL, TEXT("OK"), TEXT("IT WORKED"), MB_OK);

    Uninitialize();

    return 0;
}