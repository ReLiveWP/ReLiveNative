
#include <windows.h>
#include <shlobj.h>
#include "wlidcomm.h"
#include "log.h"
#include "util.h"
#include "ioctls.h"
#include "storage.h"
#include "globals.h"
#include "update.h"
#include "deviceid.h"

#include <curl/curl.h>
#include <mbedtls/psa_util.h>
#include <sqlite3.h>

#include <tlhelp32.h>

#ifndef TH32CS_GETALLMODS
#define TH32CS_GETALLMODS 0
#endif

#if _WIN64
#define ADDRESS_PRINTF L"0x%016x"
#else
#define ADDRESS_PRINTF L"0x%08x"
#endif

using namespace wlidsvc;
using namespace wlidsvc::globals;
using namespace wlidsvc::storage;

extern "C"
{
    LONG WINAPI WLI_ExceptionHandler(struct _EXCEPTION_POINTERS *pExceptionInfo)
    {
        LOG("Is this thing on?? ExceptionHandler called in service!!! ExceptionCode=0x%08x; ExceptionAddress=0x%08x; ExceptionInformation=0x%08x;",
            pExceptionInfo->ExceptionRecord->ExceptionCode,
            pExceptionInfo->ExceptionRecord->ExceptionAddress,
            pExceptionInfo->ExceptionRecord->ExceptionInformation);

        if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
        {
            const char* attempt = pExceptionInfo->ExceptionRecord->ExceptionInformation[0] ? "READ" : "WRITE";
            LOG("Attempt to %s at address " ADDRESS_PRINTF, attempt, pExceptionInfo->ExceptionRecord->ExceptionInformation[1]);
        }
        else
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE | TH32CS_GETALLMODS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
        {
            LOG("%s", "Failed to CreateToolhelp32Snapshot, you're going in blind!!");
            return EXCEPTION_CONTINUE_SEARCH;
        }

#if defined(UNDER_CE) && defined(ARM)
        auto ContextRecord = pExceptionInfo->ContextRecord;
        auto SP = (DWORD_PTR *)ContextRecord->Sp;
        LOG_WIDE(L"Registers: R0=" ADDRESS_PRINTF L"; R1=" ADDRESS_PRINTF L"; R2=" ADDRESS_PRINTF L"; R3=" ADDRESS_PRINTF L";\n"
                 L"R4=" ADDRESS_PRINTF L"; R5=" ADDRESS_PRINTF L"; R6=" ADDRESS_PRINTF L"; R7=" ADDRESS_PRINTF L";\n"
                 L"R8=" ADDRESS_PRINTF L"; R9=" ADDRESS_PRINTF L"; R10=" ADDRESS_PRINTF L"; R11=" ADDRESS_PRINTF L";\n"
                 L"R12=" ADDRESS_PRINTF L"; SP=" ADDRESS_PRINTF L"; LR=" ADDRESS_PRINTF L"; PC=" ADDRESS_PRINTF L"; PSR=" ADDRESS_PRINTF L";",
                 ContextRecord->R0, ContextRecord->R1, ContextRecord->R2, ContextRecord->R3,
                 ContextRecord->R4, ContextRecord->R5, ContextRecord->R6, ContextRecord->R7,
                 ContextRecord->R8, ContextRecord->R9, ContextRecord->R10, ContextRecord->R11,
                 ContextRecord->R12, ContextRecord->Sp, ContextRecord->Lr, ContextRecord->Pc, ContextRecord->Psr);
#elif defined(__x86_64__)
        auto ContextRecord = pExceptionInfo->ContextRecord;
        auto SP = (DWORD_PTR *)ContextRecord->Rsp;
#endif

        MODULEENTRY32 mod = {0};
        PROCESSENTRY32 proc{0};
        mod.dwSize = sizeof(MODULEENTRY32);
        proc.dwSize = sizeof(PROCESSENTRY32);

        if (Module32First(hSnapshot, &mod))
        {
            do
            {
                LOG(L"Module: %s @ " ADDRESS_PRINTF " size: " ADDRESS_PRINTF, util::wstring_to_utf8(mod.szModule).c_str(), mod.modBaseAddr, mod.modBaseSize);
            } while (Module32Next(hSnapshot, &mod));
        }

#ifdef UNDER_CE
        CloseToolhelp32Snapshot(hSnapshot);
#else
        CloseHandle(hSnapshot);
#endif

        return EXCEPTION_CONTINUE_SEARCH;
    }

    // extern void init_errno(void);

    DWORD_PTR WLI_Init(DWORD_PTR hContext)
    {
        // init_errno();

        psa_crypto_init();
        curl_global_init(CURL_GLOBAL_DEFAULT);
        InitializeCriticalSection(&g_wlidSvcReadyCritSect);
        InitializeCriticalSection(&g_ClientConfigCritSect);
        InitializeCriticalSection(&g_dbCritSect);
        g_tlsIsImpersonatedIdx = TlsAlloc();

        LOG("%s", "WLI_Init called!");

        {
            util::critsect_t cs{&g_wlidSvcReadyCritSect};
            if (g_hWlidSvcReady == NULL)
            {
                g_hWlidSvcReady = CreateEvent(NULL, TRUE, FALSE, WLIDSVC_READY_EVENT);
            }
        }

        {
            int rc;
            if ((rc = init_db()) != SQLITE_OK)
            {
                // ideally wait for a logger connection
                LOG("%s: %d", "failed db init:", rc);
                Sleep(1000);
                // return FALSE;
            }
        }

        CreateThread(NULL, 0, CheckForUpdatesThreadProc, NULL, 0, NULL);
        SetEvent(g_hWlidSvcReady);

#ifdef UNDER_CE
        AddVectoredExceptionHandler(1, WLI_ExceptionHandler);
#endif

        return TRUE;
    }

    BOOL WLI_Deinit(DWORD_PTR hContext)
    {
        return FALSE;
    }

    DWORD_PTR WLI_Open(DWORD_PTR hContext, DWORD dwAccess, DWORD dwShareMode)
    {
        return (DWORD_PTR)(new (std::nothrow) wlidsvc::handle_ctx_t(InterlockedIncrement(&g_instanceCount)));
    }

    BOOL WLI_Close(DWORD_PTR hContext)
    {
        LOG("WLI_Close called for context %p", hContext);
        delete ((wlidsvc::handle_ctx_t *)hContext);
        LOG("Context %p closed, remaining instance count: %d", hContext, InterlockedDecrement(&g_instanceCount));
        return TRUE;
    }

    DWORD WLI_Write(DWORD_PTR hContext, LPCVOID pInBuf, DWORD dwInLen)
    {
        return (DWORD)-1;
    }

    DWORD WLI_Read(DWORD_PTR hContext, LPVOID pBuf, DWORD dwLen)
    {
        return (DWORD)-1;
    }

    BOOL WLI_IOControl(DWORD_PTR hContext, DWORD dwCode, PBYTE pBufIn,
                       DWORD dwLenIn, PBYTE pBufOut, DWORD dwLenOut,
                       PDWORD pdwActualOut)
    {
        if (hContext == 0)
            return FALSE;

        auto hCtx = (wlidsvc::handle_ctx_t *)hContext;
        util::critsect_t cs{&hCtx->cs};

        BEGIN_IOCTL_MAP()
        IOCTL_HANDLER_NO_LOG(IOCTL_WLIDSVC_LOG_MESSAGE, WLI_HandleLogMessage)
        IOCTL_HANDLER_NO_LOG(IOCTL_WLIDSVC_LOG_MESSAGE_WIDE, WLI_HandleLogMessageWide)
        IOCTL_HANDLER(IOCTL_WLIDSVC_INIT_HANDLE, WLI_InitHandle);
        IOCTL_HANDLER(IOCTL_WLIDSVC_GET_DEFAULT_ID, WLI_GetDefaultID);
        IOCTL_HANDLER(IOCTL_WLIDSVC_CREATE_IDENTITY_HANDLE, WLI_CreateIdentityHandle);
        IOCTL_HANDLER(IOCTL_WLIDSVC_CLOSE_IDENTITY_HANDLE, WLI_CloseIdentityHandle);
        IOCTL_HANDLER(IOCTL_WLIDSVC_GET_LIVE_ENVIRONMENT, WLI_GetLiveEnvironment);
        IOCTL_HANDLER(IOCTL_WLIDSVC_GET_IDENTITY_PROPERTY_BY_NAME, WLI_GetIdentityPropertyByName);
        IOCTL_HANDLER(IOCTL_WLIDSVC_SET_CREDENTIAL, WLI_SetCredential);
        IOCTL_HANDLER(IOCTL_WLIDSVC_GET_AUTH_STATE_EX, WLI_GetAuthStateEx);
        IOCTL_HANDLER(IOCTL_WLIDSVC_AUTH_IDENTITY_TO_SERVICE_EX, WLI_AuthIdentityToServiceEx);
        IOCTL_HANDLER(IOCTL_WLIDSVC_LOGON_IDENTITY_EX, WLI_LogonIdentityEx);
        IOCTL_HANDLER(IOCTL_WLIDSVC_AUTH_IDENTITY_TO_SERVICE, WLI_AuthIdentityToService);
        IOCTL_HANDLER(IOCTL_WLIDSVC_PERSIST_CREDENTIAL, WLI_PersistCredential);
        IOCTL_HANDLER(IOCTL_WLIDSVC_ENUM_IDENTITIES_WITH_CACHED_CREDENTIALS, WLI_EnumIdentitiesWithCachedCredentials);
        IOCTL_HANDLER(IOCTL_WLIDSVC_CLOSE_ENUM_IDENTITIES_HANDLE, WLI_CloseEnumIdentitiesHandle);
        IOCTL_HANDLER(IOCTL_WLIDSVC_SET_IDENTITY_PROPERTY, WLI_SetIdentityProperty);
        IOCTL_HANDLER(IOCTL_WLIDSVC_GET_DEVICE_ID, WLI_GetDeviceId);
        END_IOCTL_MAP()

        return FALSE;
    }

    DWORD WLI_Seek(DWORD_PTR hContext, long pos, DWORD type)
    {
        return (DWORD)-1;
    }

    void WLI_PowerUp(void)
    {
        return;
    }

    void WLI_PowerDown(void)
    {
        return;
    }
}