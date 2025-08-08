#include <errno.h>
#include <locale.h>
#include <windows.h>

static DWORD gTLSIndex;
static CRITICAL_SECTION gCS;
static lconv gLconv = {".", ","};

void init_errno(void)
{
    gTLSIndex = TlsAlloc();
    InitializeCriticalSection(&gCS);
}

lconv *localeconv(void)
{
    return &gLconv;
}

// TODO: this really should be in a critical section
int *__errno_location(void)
{
    EnterCriticalSection(&gCS);
    LPVOID val = TlsGetValue(gTLSIndex);
    if (val == 0)
    {
        int *i = malloc(sizeof(int));
        TlsSetValue(gTLSIndex, i);
        LeaveCriticalSection(&gCS);
        return i;
    }

    LeaveCriticalSection(&gCS);
    return (int *)val;
}