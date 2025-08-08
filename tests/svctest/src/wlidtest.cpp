#include <windows.h>

#ifdef UNDER_CE
#define wWinMain WinMain
#undef GetProcAddress
#define GetProcAddress(hInst, x) GetProcAddressW(hInst, TEXT(x))
#endif

typedef void (*TEST_InitHooks)(void);
typedef HRESULT (*msidcrl_Initialize)(GUID *lpGuid, DWORD dwVersionMajor, DWORD dwVersionMinor);

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
    GUID gidReference;
    HRESULT hCreateGuid = CoCreateGuid(&gidReference);

    HMODULE hMsidcrl = LoadLibrary(TEXT("msidcrl"));
    TEST_InitHooks InitHooks = (TEST_InitHooks)GetProcAddress(hMsidcrl, "TEST_InitHooks");
    msidcrl_Initialize Initialize = (msidcrl_Initialize)GetProcAddress(hMsidcrl, "Initialize");
    InitHooks();
    Initialize(&gidReference, 1, 0);

    MessageBox(NULL, TEXT("OK"), TEXT("IT WORKED"), MB_OK);

    return 0;
}