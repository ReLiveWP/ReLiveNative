#include <windows.h>
#include "msidcrl.h"

#ifdef UNDER_CE
#define wWinMain WinMain
#undef GetProcAddress
#define GetProcAddress(hInst, x) GetProcAddressW(hInst, TEXT(x))
#endif

typedef void (*TEST_InitHooks)(void);
typedef HRESULT (*msidcrl_Initialize)(GUID *lpGuid, DWORD dwVersionMajor, DWORD dwVersionMinor);
typedef HRESULT (*msidcrl_Uninitialize)(void);

typedef HRESULT (*msidcrl_CreateIdentityHandle)(LPCWSTR szMemberName, DWORD dwIdentityFlags, HIDENTITY *phIdentity);
typedef HRESULT (*msidcrl_CloseIdentityHandle)(HIDENTITY hIdentity);

typedef HRESULT (*msidcrl_SetCredential)(HIDENTITY hIdentity, LPCWSTR szCredentialType, LPCWSTR szCredentialValue);
typedef HRESULT (*msidcrl_LogonIdentityEx)(HIDENTITY hIdentity, LPCWSTR szAuthPolicy, DWORD dwAuthFlags, RSTParams *pcRSTParams, DWORD dwpcRSTParamsCount);

#ifdef UNDER_CE
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nShowCmd)
#else
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
#endif
{
    GUID gidReference;
    HRESULT hCreateGuid = CoCreateGuid(&gidReference);

    HMODULE hMsidcrl = LoadLibrary(TEXT("msidcrl"));
    TEST_InitHooks InitHooks = (TEST_InitHooks)GetProcAddress(hMsidcrl, "TEST_InitHooks");
    msidcrl_Initialize Initialize = (msidcrl_Initialize)GetProcAddress(hMsidcrl, "Initialize");
    msidcrl_CreateIdentityHandle CreateIdentityHandle = (msidcrl_CreateIdentityHandle)GetProcAddress(hMsidcrl, "CreateIdentityHandle");
    msidcrl_CloseIdentityHandle CloseIdentityHandle = (msidcrl_CloseIdentityHandle)GetProcAddress(hMsidcrl, "CloseIdentityHandle");
    msidcrl_LogonIdentityEx LogonIdentityEx = (msidcrl_LogonIdentityEx)GetProcAddress(hMsidcrl, "LogonIdentityEx");
    msidcrl_SetCredential SetCredential = (msidcrl_SetCredential)GetProcAddress(hMsidcrl, "SetCredential");
    msidcrl_Uninitialize Uninitialize = (msidcrl_Uninitialize)GetProcAddress(hMsidcrl, "Uninitialize");

    InitHooks();
    Initialize(&gidReference, 1, 0);

    HIDENTITY hIdentity = nullptr;
    HRESULT hr = CreateIdentityHandle(TEXT("test@test.com"), 0, &hIdentity);
    if (FAILED(hr))
    {
        MessageBox(NULL, TEXT("Failed to create identity handle"), TEXT("Error"), MB_OK | MB_ICONERROR);
        return -1;
    }

    hr = SetCredential(hIdentity, TEXT("ps:password"), TEXT("test"));
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