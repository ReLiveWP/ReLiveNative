
#include "msidcrl.h"
#include "logging.h"
#include "wlidcomm.h"
#include "msidcrl_int.h"

#include <wincrypt.h>
#include <wininet.h>

#ifndef CERT_SYSTEM_STORE_CURRENT_USER
#define CERT_SYSTEM_STORE_LOCATION_SHIFT 16
#define CERT_SYSTEM_STORE_CURRENT_USER_ID 1
#define CERT_SYSTEM_STORE_CURRENT_USER (CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT)
#endif

using namespace msidcrl::globals;

extern "C"
{
#if WLIDSVC_INPROC
    void TEST_InitHooks(void);
#endif

    class critsect_t
    {
    public:
        inline critsect_t(LPCRITICAL_SECTION cs) : m_cs(cs) { EnterCriticalSection(m_cs); }
        inline ~critsect_t() { LeaveCriticalSection(m_cs); }

    private:
        LPCRITICAL_SECTION m_cs;
    };

    HRESULT Initialize(GUID *lpGuid, DWORD dwVersionMajor, DWORD dwVersionMinor)
    {
#if WLIDSVC_INPROC
        TEST_InitHooks();
#endif
#ifdef UNDER_CE
        AddVectoredExceptionHandler(1, MSIDCRL_ExceptionHandler);
#endif

        critsect_t cs{&g_hDriverCrtiSec};

        IOCTL_INIT_HANDLE_ARGS args = {};
        HANDLE hEvent, hDriver;
        HRESULT hr = S_OK;

        args.dwApiLevel = WLIDSVC_API_LEVEL;
        args.dwMajorVersion = dwVersionMajor;
        args.dwMinorVersion = dwVersionMinor;
        GetModuleFileName(NULL, args.szExecutable, MAX_PATH);
        memcpy(&args.gApp, lpGuid, sizeof(GUID));

        // unlike the original WLIDSVC, we need our driver handle at all times
        hDriver = CreateFile(WLIDSVC_FILE, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hDriver == INVALID_HANDLE_VALUE)
        {
            ActivateDevice(WLIDSVC_NAME, 0);

            hDriver = CreateFile(WLIDSVC_FILE, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
            if (hDriver == INVALID_HANDLE_VALUE)
            {
                goto error;
            }
        }

        g_hDriver = hDriver;

        hEvent = CreateEvent(NULL, TRUE, FALSE, WLIDSVC_READY_EVENT);
        if (hEvent != 0)
        {
            WaitForSingleObject(hEvent, 180000);
            CloseHandle(hEvent);
            hEvent = 0;
        }

        if (FAILED(hr = DeviceIoControl(hDriver, IOCTL_WLIDSVC_INIT_HANDLE, &args, sizeof(IOCTL_INIT_HANDLE_ARGS), NULL, 0, NULL, NULL)))
            return hr;

        return S_OK;

    error:
        if (hDriver)
            CloseHandle(hDriver);
        if (hEvent)
            CloseHandle(hEvent);
        return -1;
    }

    HRESULT InitializeEx(GUID *lpGuid, DWORD dwVersionMajor, DWORD dwVersionMinor, IDCRL_OPTION *lpOptions, DWORD cbOptions)
    {
        // for now
        return Initialize(lpGuid, dwVersionMajor, dwVersionMinor);
    }

    HRESULT Uninitialize()
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE(TEXT("Uninitialize"));

        if (g_hDriver)
        {
            CloseHandle(g_hDriver);
            g_hDriver = NULL;
        }

        return S_OK;
    }

#define PPCRL_S_TOKEN_TYPE_DOES_NOT_SUPPORT_SESSION_KEY 0x48861

    HRESULT AuthIdentityToService(
        IN HIDENTITY hIdentity,
        IN LPCWSTR szServiceTarget,
        IN OPTIONAL LPCWSTR szServicePolicy,
        IN DWORD dwTokenRequestFlags,
        OUT OPTIONAL LPWSTR *szToken,
        OUT OPTIONAL DWORD *pdwResultFlags,
        OUT OPTIONAL BYTE **ppbSessionKey,
        OUT OPTIONAL DWORD *pcbSessionKeyLength)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(
            TEXT("AuthIdentityToService: hIdentity=0x%08hx; szServiceTarget=%s; szServicePolicy=%s; dwTokenRequestFlags=%d; szToken=0x%08hx; pdwResultFlags=0x%08hx; ppbSessionKey=0x%08hx; pcbSessionKeyLength=0x%08hx;"),
            hIdentity,
            LOG_STRING(szServiceTarget),
            LOG_STRING(szServicePolicy),
            dwTokenRequestFlags,
            szToken,
            pdwResultFlags,
            ppbSessionKey,
            pcbSessionKeyLength);

        if (szServiceTarget == nullptr)
        {
            return E_INVALIDARG;
        }

        if (ppbSessionKey != nullptr || pcbSessionKeyLength != nullptr)
        {
            LOG_MESSAGE(TEXT("AuthIdentityToService requested ppbSessionKey and idk what that does yet so"));
            // return E_NOTIMPL;
        }

        HRESULT hr;
        IOCTL_AUTH_IDENTITY_TO_SERVICE_ARGS args{};
        IOCTL_AUTH_IDENTITY_TO_SERVICE_RETURN ret{};
        args.hIdentity = hIdentity->hIdentitySrv;
        args.dwTokenRequestFlags = dwTokenRequestFlags;

        if (szServiceTarget != nullptr)
            wcsncpy(args.szServiceTarget, szServiceTarget, 256);
        else
            memset(args.szServiceTarget, 0, 256 * sizeof(WCHAR));

        if (szServicePolicy != nullptr)
            wcsncpy(args.szServicePolicy, szServicePolicy, 64);
        else
            memset(args.szServicePolicy, 0, 64 * sizeof(WCHAR));

        if (FAILED(hr = DeviceIoControl(g_hDriver,
                                        IOCTL_WLIDSVC_AUTH_IDENTITY_TO_SERVICE,
                                        &args, sizeof(IOCTL_AUTH_IDENTITY_TO_SERVICE_ARGS),
                                        &ret, sizeof(IOCTL_AUTH_IDENTITY_TO_SERVICE_RETURN),
                                        NULL, NULL)))
            return hr;

        if (szToken != nullptr)
        {
            auto len = wcslen(ret.szToken);
            auto szTokenPtr = (LPWSTR)calloc((len + 1), sizeof(WCHAR));
            if (szTokenPtr == nullptr)
                return E_OUTOFMEMORY;

            wcscpy(szTokenPtr, ret.szToken);
            szTokenPtr[len] = L'\0';

            *szToken = szTokenPtr;
        }

        if (pdwResultFlags != nullptr)
        {
            *pdwResultFlags = ret.dwResultFlags;
        }

        if (ppbSessionKey != nullptr)
        {
            // auto len = wcslen(ret.szToken);
            // auto szTokenPtr = (LPWSTR)malloc((len + 1) * sizeof(WCHAR));
            // if (szTokenPtr == nullptr)
            //     return E_OUTOFMEMORY;

            // wcsncpy(szTokenPtr, ret.szToken, 1024);
            // szTokenPtr[len] = L'\0';

            // *ppbSessionKey = (LPBYTE)szTokenPtr;
            // if (pcbSessionKeyLength != nullptr)
            //     *pcbSessionKeyLength = (len) * sizeof(WCHAR);

            // unconvinced these are ever correctly set??
            *ppbSessionKey = NULL;

            // return PPCRL_S_TOKEN_TYPE_DOES_NOT_SUPPORT_SESSION_KEY;
        }

        if (pcbSessionKeyLength != nullptr)
        {
            *pcbSessionKeyLength = 0;
        }
        

        return S_OK;
    }

    HRESULT AuthIdentityToServiceEx(
        IN HIDENTITY hIdentity,
        IN DWORD serviceTokenFlags,
        IN LPRSTParams pParams,
        IN DWORD dwParamCount)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(
            TEXT("AuthIdentityToServiceEx: hIdentity=%08hx; serviceTokenFlags=%d; pParams=%08hx; dwParamCount=%d;"),
            hIdentity, serviceTokenFlags, pParams, dwParamCount);

        if (hIdentity == nullptr || pParams == nullptr || dwParamCount == 0)
        {
            return E_INVALIDARG;
        }

        HRESULT hr;
        GUID guid;
        HANDLE hMap = NULL;
        DWORD dwFileSize = 0;
        if (FAILED(hr = SerializeRSTParams(pParams, dwParamCount, &guid, &hMap, &dwFileSize)))
            return hr;

        IOCTL_AUTH_IDENTITY_TO_SERVICE_EX_ARGS args = {};
        args.hIdentity = hIdentity->hIdentitySrv;
        args.dwServiceTokenFlags = serviceTokenFlags;
        args.gMapParams = guid;
        args.dwFileSize = dwFileSize;
        args.dwParamCount = dwParamCount;

        hr = DeviceIoControl(g_hDriver,
                             IOCTL_WLIDSVC_AUTH_IDENTITY_TO_SERVICE_EX,
                             &args, sizeof(IOCTL_AUTH_IDENTITY_TO_SERVICE_EX_ARGS),
                             NULL, 0,
                             NULL, NULL);

        CloseHandle(hMap);

        return hr;
    }

    HRESULT CheckPasswordStrength(IN LPCWSTR szPassword, OUT PPCRL_PASSWORD_STRENGTH *pStrength)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("[E_NOTIMPL] CheckPasswordStrength: dwFlags=%s;"), TEXT("REDACTED"));

        if (pStrength == nullptr || szPassword == nullptr)
        {
            return E_INVALIDARG;
        }

        return E_NOTIMPL;
    }

    HRESULT CloseDeviceID(IN DWORD dwFlags, IN LPCWSTR szAdditionalParams)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("[E_NOTIMPL] CloseDeviceID: dwFlags=%d; szAdditionalParams=%s;"), dwFlags, LOG_STRING(szAdditionalParams));

        if (dwFlags == 0 && szAdditionalParams == nullptr)
        {
            // yeah this one's a lil odd, but this is what the original code does
            return E_NOTIMPL;
        }

        return E_INVALIDARG;
    }

    HRESULT EnumIdentitiesWithCachedCredentials(IN LPCWSTR szCredType, OUT HENUMIDENTITY *phEnumIdentities)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("EnumIdentitiesWithCachedCredentials: szCredType=%s;"), LOG_STRING(szCredType));

        if (phEnumIdentities == nullptr || szCredType == nullptr)
        {
            return E_INVALIDARG;
        }

        HRESULT hr;
        IOCTL_ENUM_IDENTITIES_WITH_CACHED_CREDENTIALS_ARGS args{};
        IOCTL_ENUM_IDENTITIES_WITH_CACHED_CREDENTIALS_RETURN retVal{};

        wcsncpy(args.szCredType, szCredType, 64);

        if (FAILED(hr = DeviceIoControl(g_hDriver,
                                        IOCTL_WLIDSVC_ENUM_IDENTITIES_WITH_CACHED_CREDENTIALS,
                                        &args, sizeof(IOCTL_ENUM_IDENTITIES_WITH_CACHED_CREDENTIALS_ARGS),
                                        &retVal, sizeof(IOCTL_ENUM_IDENTITIES_WITH_CACHED_CREDENTIALS_RETURN),
                                        NULL, NULL)))
            return hr;

        PENUM_IDENTITY_CREDENTIALS pEnumCreds = (PENUM_IDENTITY_CREDENTIALS)calloc(1, sizeof(ENUM_IDENTITY_CREDENTIALS));

        BYTE *pMapView;
        if (retVal.dwIdentities != 0)
        {
            WCHAR szGuid[40] = {0};
            StringFromGUID2(retVal.gIdentities, szGuid, 40);
            HANDLE hMap = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, retVal.cbIdentities, szGuid);
            if (hMap == NULL)
            {
                Server_CloseEnumIdentitiesHandle(retVal.hServerHandle);
                LOG_MESSAGE_FMT(TEXT("OpenFileMapping failed: %d"), GetLastError());
                return HRESULT_FROM_WIN32(GetLastError());
            }

            BYTE *pMapView = (BYTE *)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
            if (pMapView == NULL)
            {
                CloseHandle(hMap);
                Server_CloseEnumIdentitiesHandle(retVal.hServerHandle);
                LOG_MESSAGE_FMT(TEXT("MapViewOfFile failed: %d"), GetLastError());
                return HRESULT_FROM_WIN32(GetLastError());
            }

            pEnumCreds->hMap = hMap;
            pEnumCreds->pMapView = pMapView;

            DWORD offset = 0;
            ENUM_IDENTITY_CREDENTIALS_ITEM *root = NULL, *previous = NULL;
            for (int i = 0; i < retVal.dwIdentities; i++)
            {
                ENUM_IDENTITY_CREDENTIALS_ITEM *newItem = (ENUM_IDENTITY_CREDENTIALS_ITEM *)calloc(1, sizeof(ENUM_IDENTITY_CREDENTIALS_ITEM));
                if (root == NULL)
                    root = newItem;

                if (previous != NULL)
                    previous->next = newItem;

                LPWSTR ptr = (LPWSTR)(pMapView + offset);
                offset += (wcslen(ptr) + 1) * sizeof(WCHAR);

                newItem->szIdentity = ptr;
                previous = newItem;
            }

            pEnumCreds->root = root;
            pEnumCreds->current = root;
            pEnumCreds->hServerHandle = retVal.hServerHandle;
        }

        // there is no indication of what this function is supposed to do if there are no identities? i Think
        // from what i can tell it returns a success status, then enumerates nothing

        PPEIH hEnumIdentities = (PPEIH)calloc(1, sizeof(PEIH));
        hEnumIdentities->pEnumCreds = pEnumCreds;
        *phEnumIdentities = hEnumIdentities;

        return S_OK;
    }

    HRESULT NextIdentity(IN HENUMIDENTITY hEnum, OUT LPWSTR *pwszMemberName)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("NextIdentity: hEnum=%08hx;"), hEnum);

        if (pwszMemberName == nullptr)
            return E_POINTER;

        PENUM_IDENTITY_CREDENTIALS pEnumCreds = (PENUM_IDENTITY_CREDENTIALS)hEnum->pEnumCreds;
        if (pEnumCreds->current == nullptr)
            return E_ABORT;

        DWORD len = wcslen(pEnumCreds->current->szIdentity);
        LPWSTR wszMemberName = (LPWSTR)calloc(len + 1, sizeof(WCHAR));
        wcscpy(wszMemberName, pEnumCreds->current->szIdentity);

        *pwszMemberName = wszMemberName;
        pEnumCreds->current = pEnumCreds->current->next;

        return S_OK;
    }

    HRESULT CloseEnumIdentitiesHandle(IN HENUMIDENTITY hEnum)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("CloseEnumIdentitiesHandle: hEnum=%08hx;"), hEnum);

        if (hEnum == nullptr)
        {
            return E_INVALIDARG;
        }

        PENUM_IDENTITY_CREDENTIALS pEnumCreds = (PENUM_IDENTITY_CREDENTIALS)hEnum->pEnumCreds;
        if (pEnumCreds->current == nullptr)
            return S_FALSE;

        PENUM_IDENTITY_CREDENTIALS_ITEM item = pEnumCreds->root;
        do
        {
            if (item == NULL)
                break;

            PENUM_IDENTITY_CREDENTIALS_ITEM current = item;
            item = current->next;

            free(current);
        } while (item != NULL);

        if (pEnumCreds->pMapView != nullptr)
            UnmapViewOfFile(pEnumCreds->pMapView);
        if (pEnumCreds->hMap != NULL)
            CloseHandle(pEnumCreds->hMap);
        if (pEnumCreds->hServerHandle != 0)
            Server_CloseEnumIdentitiesHandle(pEnumCreds->hServerHandle);

        free(pEnumCreds);

        return S_OK;
    }

    HRESULT CloseIdentityHandle(IN HIDENTITY hIdentity)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("CloseIdentityHandle: hIdentity=%08hx;"), hIdentity);

        if (hIdentity == nullptr)
        {
            return E_INVALIDARG;
        }

        HRESULT hr = S_OK;
        IOCTL_CLOSE_IDENTITY_HANDLE_ARGS args{.hIdentity = hIdentity->hIdentitySrv};
        if (FAILED(hr = DeviceIoControl(g_hDriver,
                                        IOCTL_WLIDSVC_CLOSE_IDENTITY_HANDLE,
                                        &args, sizeof(IOCTL_CLOSE_IDENTITY_HANDLE_ARGS),
                                        NULL, 0,
                                        NULL, NULL)))
            return hr;

        PassportFreeMemory(hIdentity);

        return S_OK;
    }

    HRESULT CreateIdentityHandle(
        IN LPCWSTR szMemberName,
        IN DWORD dwIdentityFlags,
        OUT HIDENTITY *phIdentity)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("CreateIdentityHandle: szMemberName=%s; dwIdentityFlags=%d;"), LOG_STRING(szMemberName), dwIdentityFlags);

        if (phIdentity == nullptr)
        {
            return E_INVALIDARG;
        }

        HRESULT hr = S_OK;
        IOCTL_CREATE_IDENTITY_HANDLE_ARGS args{};
        IOCTL_CREATE_IDENTITY_HANDLE_RETURN retVal{};

        if (szMemberName != nullptr)
            wcsncpy(args.szMemberName, szMemberName, 128);
        else
            memset(args.szMemberName, 0, 128 * sizeof(WCHAR));
        args.dwIdentityFlags = dwIdentityFlags;

        if (FAILED(hr = DeviceIoControl(g_hDriver,
                                        IOCTL_WLIDSVC_CREATE_IDENTITY_HANDLE,
                                        &args, sizeof(IOCTL_CREATE_IDENTITY_HANDLE_ARGS),
                                        &retVal, sizeof(IOCTL_CREATE_IDENTITY_HANDLE_RETURN),
                                        NULL, NULL)))
            return hr;

        PPIH hIdentity = (PPIH)calloc(1, sizeof(PIH));
        if (hIdentity == NULL)
            return E_OUTOFMEMORY;

        hIdentity->hIdentitySrv = retVal.hIdentity;

        *phIdentity = hIdentity;

        return S_OK;
    }

    HRESULT CreateIdentityHandleFromAuthState(
        IN LPCWSTR szAuthToken,
        IN DWORD dwTokenFlags,
        OUT HIDENTITY *phIdentity)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("[E_NOTIMPL] CreateIdentityHandleFromAuthState: szAuthToken=%s; dwTokenFlags=%d;"), LOG_STRING(szAuthToken), dwTokenFlags);

        if (phIdentity == nullptr || szAuthToken == nullptr)
        {
            return E_INVALIDARG;
        }

        return E_NOTIMPL;
    }

    HRESULT CreateLiveIDAccount(
        IN LPCWSTR szMemberName,
        IN LPCWSTR szPassword,
        IN WLIDProperty *pProperties,
        IN DWORD dwPropertyCount,
        OUT WLIDProperty **ppProperties,
        OUT DWORD *pdwPropertyCount)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(
            TEXT("[E_NOTIMPL] CreateLiveIDAccount: szMemberName=%s; szPassword=%s; pProperties=%08hx; dwPropertyCount=%d;"),
            LOG_STRING(szMemberName),
            TEXT("REDACTED"),
            pProperties,
            dwPropertyCount);

        if (szMemberName == nullptr || szPassword == nullptr || ppProperties == nullptr ||
            pdwPropertyCount == nullptr)
        {
            return E_INVALIDARG;
        }

        return E_NOTIMPL;
    }

    HRESULT EncryptWithSessionKey(
        IN HIDENTITY hIdentity,
        IN LPCWSTR szServiceName,
        IN DWORD algIdEncrypt,
        IN DWORD algIdHash,
        IN LPCWSTR pbPlainText,
        OUT BYTE **ppbCipherText,
        OUT DWORD *pcbCipherTextLength)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(
            TEXT("[E_NOTIMPL] EncryptWithSessionKey: hIdentity=%08hx; szServiceName=%s; algIdEncrypt=%d, algIdHash=%d; pbPlainText=%s;"),
            hIdentity,
            LOG_STRING(szServiceName),
            algIdEncrypt,
            algIdHash,
            pbPlainText);

        return E_NOTIMPL;
    }

    HRESULT DecryptWithSessionKey(
        IN HIDENTITY hIdentity,
        IN LPCWSTR szServiceName,
        IN DWORD algIdEncrypt,
        IN DWORD algIdHash,
        IN BYTE *pbCipherText,
        IN DWORD cbCipherText,
        OUT LPWSTR *ppbPlainText,
        OUT DWORD *pcbPlainTextLength)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(
            TEXT("[E_NOTIMPL] DecryptWithSessionKey: hIdentity=%08hx; szServiceName=%s; algIdEncrypt=%d, algIdHash=%d;"),
            hIdentity,
            LOG_STRING(szServiceName),
            algIdEncrypt,
            algIdHash);

        return E_NOTIMPL;
    }

    HRESULT ExportAuthState(
        IN HIDENTITY hIdentity,
        IN DWORD dwFlags,
        OUT LPWSTR *szAuthToken)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("[E_NOTIMPL] ExportAuthState: hIdentity=%08hx; dwFlags=%d;"), hIdentity, dwFlags);

        if (hIdentity == nullptr || szAuthToken == nullptr)
        {
            return E_INVALIDARG;
        }

        return E_NOTIMPL;
    }

    HRESULT GetAuthState(
        IN HIDENTITY hIdentity,
        OUT OPTIONAL DWORD *pdwAuthState,
        OUT OPTIONAL DWORD *pdwAuthRequired,
        OUT OPTIONAL DWORD *pdwRequestStatus,
        OUT OPTIONAL LPWSTR *szWebFlowUrl)
    {
        LOG_MESSAGE_FMT(TEXT("GetAuthState: hIdentity=%08hx;"), hIdentity);

        return GetAuthStateEx(
            hIdentity,
            nullptr, // szServiceTarget
            pdwAuthState,
            pdwAuthRequired,
            pdwRequestStatus,
            szWebFlowUrl);
    }

    HRESULT GetAuthStateEx(
        IN HIDENTITY hIdentity,
        IN OPTIONAL LPCWSTR szServiceTarget,
        OUT OPTIONAL DWORD *pdwAuthState,
        OUT OPTIONAL DWORD *pdwAuthRequired,
        OUT OPTIONAL DWORD *pdwRequestStatus,
        OUT OPTIONAL LPWSTR *szWebFlowUrl)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("GetAuthStateEx: hIdentity=%08hx; szServiceTarget=%s; pdwAuthState=%08hx; pdwAuthRequired=%08hx; pdwRequestStatus=%08hx; szWebFlowUrl=%08hx;"),
                        hIdentity,
                        LOG_STRING(szServiceTarget),
                        pdwAuthState,
                        pdwAuthRequired,
                        pdwRequestStatus,
                        szWebFlowUrl);

        if (hIdentity == nullptr)
        {
            return E_INVALIDARG;
        }

        IOCTL_GET_AUTH_STATE_EX_ARGS args{};
        IOCTL_GET_AUTH_STATE_EX_RETURN retVal{};

        args.hIdentity = hIdentity->hIdentitySrv;
        if (szServiceTarget != nullptr)
            wcsncpy(args.szServiceTarget, szServiceTarget, 256);
        else
            memset(args.szServiceTarget, 0, 256 * sizeof(WCHAR));

        HRESULT hr = S_OK;
        if (FAILED(hr = DeviceIoControl(g_hDriver,
                                        IOCTL_WLIDSVC_GET_AUTH_STATE_EX,
                                        &args, sizeof(IOCTL_GET_AUTH_STATE_EX_ARGS),
                                        &retVal, sizeof(IOCTL_GET_AUTH_STATE_EX_RETURN),
                                        NULL, NULL)))
            return hr;

        if (pdwAuthState != nullptr)
            *pdwAuthState = retVal.dwAuthState;
        if (pdwAuthRequired != nullptr)
            *pdwAuthRequired = retVal.dwAuthRequired;
        if (pdwRequestStatus != nullptr)
            *pdwRequestStatus = retVal.dwRequestStatus;

        if (szWebFlowUrl != nullptr)
        {
            if (retVal.szWebFlowUrl[0] != L'\0')
            {
                size_t len = wcslen(retVal.szWebFlowUrl);
                LPWSTR pszWebFlowUrl = (LPWSTR)calloc((len + 1), sizeof(WCHAR));
                if (pszWebFlowUrl == nullptr)
                    return E_OUTOFMEMORY;

                wcsncpy(pszWebFlowUrl, retVal.szWebFlowUrl, len + 1);
                pszWebFlowUrl[len] = L'\0';

                *szWebFlowUrl = pszWebFlowUrl;
            }
            else
            {
                *szWebFlowUrl = nullptr;
            }
        }

        return S_OK;
    }

    HRESULT GetDefaultID(OUT LPWSTR *szDefaultID)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        IOCTL_GET_DEFAULT_ID_RETURN sData{};
        LOG_MESSAGE(TEXT("GetDefaultID"));

        if (szDefaultID == nullptr)
        {
            return E_INVALIDARG;
        }

        // *szDefaultID = nullptr;
        HRESULT hr = S_OK;
        if (FAILED(hr = (HRESULT)DeviceIoControl(g_hDriver,
                                                 IOCTL_WLIDSVC_GET_DEFAULT_ID,
                                                 NULL, 0,
                                                 &sData, sizeof(IOCTL_GET_DEFAULT_ID_RETURN),
                                                 NULL,
                                                 NULL)) ||
            hr == S_FALSE)
        {
            *szDefaultID = nullptr;
            return hr;
        }

        auto len = wcslen(sData.szDefaultId);
        auto pszDefaultID = (LPWSTR)calloc((len + 1), sizeof(WCHAR));
        wcsncpy(pszDefaultID, sData.szDefaultId, len + 1);
        // pszDefaultID[len] = 0;

        *szDefaultID = pszDefaultID;

        return S_OK;
    }

    HRESULT GetDeviceId(
        IN DWORD dwFlags,
        IN LPCWSTR pvAdditionalParams,
        OUT LPWSTR *pwszDeviceId,
        OUT PCCERT_CONTEXT *didCertContext)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        if (g_hDriver == nullptr)
        {
            GUID guid{0};
            Initialize(&guid, 1, 0);
        }

        LOG_MESSAGE_FMT(TEXT("GetDeviceId: dwFlags=%d; pvAdditionalParams=%s; pwszDeviceId=0x%08x; didCertContext=0x%08x;"), dwFlags, LOG_STRING(pvAdditionalParams), pwszDeviceId, didCertContext);

        IOCTL_GET_DEVICE_ID_ARGS args{};
        IOCTL_GET_DEVICE_ID_RETURN retVal{};

        if (pvAdditionalParams != nullptr)
            wcsncpy(args.szAdditionalParams, pvAdditionalParams, 256);

        args.bNeedsCert = didCertContext != nullptr;

        HRESULT hr = S_OK;
        if (FAILED(hr = DeviceIoControl(g_hDriver,
                                        IOCTL_WLIDSVC_GET_DEVICE_ID,
                                        &args, sizeof(IOCTL_GET_DEVICE_ID_ARGS),
                                        &retVal, sizeof(IOCTL_GET_DEVICE_ID_RETURN),
                                        NULL, NULL)))
            return hr;

        if (pwszDeviceId != nullptr)
        {
            auto len = wcslen(retVal.szDeviceId);
            auto pszDeviceId = (LPWSTR)calloc((len + 1), sizeof(WCHAR));
            wcsncpy(pszDeviceId, retVal.szDeviceId, len + 1);

            *pwszDeviceId = pszDeviceId;
        }

        if (didCertContext != nullptr)
        {
            PCCERT_CONTEXT pCert = NULL;
            HCERTSTORE hStore = CertOpenStore(
                (LPCSTR)CERT_STORE_PROV_SYSTEM,
                0,
                0,
                CERT_SYSTEM_STORE_CURRENT_USER,
                L"MY");

            if (!hStore)
            {
                LOG_MESSAGE_FMT(L"hStore was NULL: 0x%08x;", HRESULT_FROM_WIN32(GetLastError()))
                return HRESULT_FROM_WIN32(GetLastError());
            }

            CRYPT_HASH_BLOB hashBlob;
            hashBlob.cbData = 20;
            hashBlob.pbData = retVal.bDeviceCertThumb;

            pCert = CertFindCertificateInStore(
                hStore,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                CERT_FIND_HASH,
                &hashBlob,
                NULL);

            if (pCert)
            {
                *didCertContext = pCert;
            }
            else
            {
                LOG_MESSAGE_FMT(L"CertFindCertificateInStore failed 0x%08x;", HRESULT_FROM_WIN32(GetLastError()))
                CertCloseStore(hStore, 0);
                return HRESULT_FROM_WIN32(GetLastError());
            }

            CertCloseStore(hStore, 0);
        }

        return S_OK;
    }

    HRESULT GetExtendedError(
        IN HIDENTITY hIdentity,
        OUT DWORD *pdwErrorCategory,
        OUT DWORD *pdwErrorCode,
        OUT LPWSTR *szErrorBlob)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("[E_NOTIMPL] GetExtendedError: hIdentity=%08hx;"), hIdentity);

        if (hIdentity == nullptr || pdwErrorCategory == nullptr || pdwErrorCode == nullptr ||
            szErrorBlob == nullptr)
        {
            return E_INVALIDARG;
        }

        return E_NOTIMPL;
    }

    HRESULT GetExtendedProperty(
        IN LPCWSTR szPropertyName,
        OUT LPWSTR *szPropertyValue)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("[E_NOTIMPL] GetExtendedProperty: szPropertyName=%s;"), LOG_STRING(szPropertyName));

        if (szPropertyName == nullptr || szPropertyValue == nullptr)
        {
            return E_INVALIDARG;
        }

        return E_NOTIMPL;
    }

    HRESULT GetHIPChallenge(
        IN HIDENTITY hIdentity,
        IN LPCWSTR szUnknown1,
        OUT LPWSTR *szChallenge)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("[E_NOTIMPL] GetHIPChallenge: hIdentity=%08hx; szUnknown1=%s;"), hIdentity, LOG_STRING(szUnknown1));

        if (hIdentity == nullptr || szUnknown1 == nullptr || szChallenge == nullptr)
        {
            return E_INVALIDARG;
        }

        *szChallenge = nullptr;

        return E_NOTIMPL;
    }

    HRESULT GetIdentityPropertyByName(
        IN HIDENTITY hIdentity,
        IN LPCWSTR szPropertyName,
        OUT LPWSTR *szPropertyValue)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("GetIdentityPropertyByName: hIdentity=%08hx; szPropertyName=%s;"), hIdentity, LOG_STRING(szPropertyName));

        if (hIdentity == nullptr || szPropertyName == nullptr || szPropertyValue == nullptr)
        {
            return E_INVALIDARG;
        }

        HRESULT hr = S_OK;
        IOCTL_GET_IDENTITY_PROPERTY_BY_NAME_ARGS args{};
        IOCTL_GET_IDENTITY_PROPERTY_BY_NAME_RETURN retVal{};

        args.hIdentity = hIdentity->hIdentitySrv;
        if (szPropertyName != nullptr)
            wcsncpy(args.szPropertyName, szPropertyName, 128);

        if (FAILED(hr = DeviceIoControl(g_hDriver,
                                        IOCTL_WLIDSVC_GET_IDENTITY_PROPERTY_BY_NAME,
                                        &args, sizeof(IOCTL_GET_IDENTITY_PROPERTY_BY_NAME_ARGS),
                                        &retVal, sizeof(IOCTL_GET_IDENTITY_PROPERTY_BY_NAME_RETURN),
                                        NULL, NULL)))
            return hr;

        auto len = wcslen(retVal.szPropertyValue);
        if (len == 0)
        {
            *szPropertyValue = nullptr;
            return S_FALSE;
        }

        auto pszPropertyValue = (LPWSTR)calloc((len + 1), sizeof(WCHAR));
        if (pszPropertyValue == nullptr)
            return E_OUTOFMEMORY;

        wcscpy(pszPropertyValue, retVal.szPropertyValue);
        pszPropertyValue[len] = L'\0';

        *szPropertyValue = pszPropertyValue;

        return S_OK;
    }

    HRESULT GetLiveEnvironment(OUT DWORD *pdwEnvironment)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE(TEXT("GetLiveEnvironment"));
        if (pdwEnvironment == nullptr)
        {
            return E_INVALIDARG;
        }

#ifdef IS_PRODUCTION_BUILD
        *pdwEnvironment = 0;
#else
        *pdwEnvironment = 1;
#endif

        return S_OK;
    }

    HRESULT GetPassword(IN LPCWSTR szUnk1, OUT LPWSTR *pwszUnk2)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("GetPassword: szUnk1=%s;"), LOG_STRING(szUnk1));

        if (szUnk1 == nullptr || pwszUnk2 == nullptr)
        {
            return E_INVALIDARG;
        }

        HRESULT hr = S_OK;
        HIDENTITY hIdent = NULL;
        if (FAILED(hr = CreateIdentityHandle(szUnk1, 0, &hIdent)))
            return hr;

        if (FAILED(hr = AuthIdentityToService(hIdent, L"http://Passport.NET/tb", L"LEGACY", 0x00010000, pwszUnk2, NULL, NULL, NULL)))
        {
            CloseIdentityHandle(hIdent);
            return hr;
        }

        CloseIdentityHandle(hIdent);
        return S_OK;
    }

    HRESULT GetResponseForHttpChallenge(
        IN HIDENTITY hIdentity,
        IN DWORD dwAuthFlags,
        IN DWORD dwSSOFlags,
        IN UIParam *pcUIParam,
        IN LPCWSTR wszServiceTarget,
        IN LPCWSTR wszChallenge,
        OUT LPWSTR *pwszResponse)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("[E_NOTIMPL] GetResponseForHttpChallenge: hIdentity=%08hx; dwAuthFlags=%d; dwSSOFlags=%d; pcUIParam=%08hx; wszServiceTarget=%s; wszChallenge=%s;"),
                        hIdentity,
                        dwAuthFlags,
                        dwSSOFlags,
                        pcUIParam,
                        LOG_STRING(wszServiceTarget),
                        LOG_STRING(wszChallenge));

        if (hIdentity == nullptr || wszServiceTarget == nullptr || wszChallenge == nullptr ||
            pwszResponse == nullptr)
        {
            return E_INVALIDARG;
        }

        return E_NOTIMPL;
    }

    HRESULT GetUserExtendedProperty(IN LPCWSTR userName, IN LPCWSTR propertyName, OUT LPWSTR *propertyValue)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("[E_NOTIMPL] GetUserExtendedProperty: userName=%s; propertyName=%s;"), LOG_STRING(userName), LOG_STRING(propertyName));

        if (userName == nullptr || propertyName == nullptr || propertyValue == nullptr)
        {
            return E_INVALIDARG;
        }

        return E_NOTIMPL;
    }

    HRESULT GetWebAuthUrlEx(
        IN HIDENTITY hIdentity,
        IN DWORD dwWebAuthFlag,
        IN OPTIONAL LPCWSTR szTargetServiceName,
        IN OPTIONAL LPCWSTR szServicePolicy,
        IN LPCWSTR szAdditionalPostParams,
        OUT LPWSTR *pwszWebAuthUrl,
        OUT LPWSTR *pwszPostData)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("[E_NOTIMPL] GetWebAuthUrlEx: hIdentity=%08hx; dwWebAuthFlag=%d; szTargetServiceName=%s; szServicePolicy=%s; szAdditionalPostParams=%s;"),
                        hIdentity,
                        dwWebAuthFlag,
                        LOG_STRING(szTargetServiceName),
                        LOG_STRING(szServicePolicy),
                        LOG_STRING(szAdditionalPostParams));

        return E_NOTIMPL;
    }

    HRESULT HasPersistedCredential(IN HIDENTITY hIdentity, IN LPCWSTR szCredType, OUT BOOL *bHasPersistentCred)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("[E_NOTIMPL] HasPersistedCredential: hIdentity=%08hx; szCredType=%s;"),
                        hIdentity,
                        LOG_STRING(szCredType));

        return E_NOTIMPL;
    }

    HRESULT HasSetCredential(IN HIDENTITY hIdentity, OUT BOOL *bHasSetCred)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("[E_NOTIMPL] HasPersistedCredential: hIdentity=%08hx;"), hIdentity);
        return E_NOTIMPL;
    }

    HRESULT LogonIdentityEx(
        IN HIDENTITY hIdentity,
        OPTIONAL IN LPCWSTR szAuthPolicy,
        IN DWORD dwAuthFlags,
        IN OPTIONAL RSTParams *pcRSTParams,
        IN OPTIONAL DWORD dwpcRSTParamsCount)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("LogonIdentityEx: hIdentity=%08hx; szAuthPolicy=%s; dwAuthFlags=%d, pcRSTParams=%08hx; dwpcRSTParamsCount=%d"),
                        hIdentity,
                        LOG_STRING(szAuthPolicy),
                        dwAuthFlags,
                        pcRSTParams,
                        dwpcRSTParamsCount);

        if (hIdentity == nullptr)
        {
            return E_INVALIDARG;
        }

        IOCTL_LOGON_IDENTITY_EX_ARGS args{};
        args.hIdentity = hIdentity->hIdentitySrv;
        if (szAuthPolicy != nullptr)
            wcsncpy(args.szAuthPolicy, szAuthPolicy, 256);

        args.dwAuthFlags = dwAuthFlags;
        args.dwParamCount = dwpcRSTParamsCount;

        HRESULT hr;
        GUID guid;
        HANDLE hMap = NULL;
        DWORD dwFileSize = 0;
        if (FAILED(hr = SerializeRSTParams(pcRSTParams, dwpcRSTParamsCount, &guid, &hMap, &dwFileSize)))
            return hr;

        args.gMapParams = guid;
        args.dwFileSize = dwFileSize;

        hr = DeviceIoControl(g_hDriver,
                             IOCTL_WLIDSVC_LOGON_IDENTITY_EX,
                             &args, sizeof(IOCTL_LOGON_IDENTITY_EX_ARGS),
                             NULL, 0,
                             NULL, NULL);

        CloseHandle(hMap);
        return hr;
    }

    HRESULT PassportFreeMemory(IN OUT void *o)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("PassportFreeMemory: o=0x%08x;"), o);

        if (o == nullptr)
            return S_FALSE;

        free(o);
        return S_OK;
    }

    HRESULT PersistCredential(IN HIDENTITY hIdentity, IN LPCWSTR lpCredType)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("PersistCredential: hIdentity=%08hx; lpCredType=%s;"), hIdentity, LOG_STRING(lpCredType));

        IOCTL_PERSIST_CREDENTIAL_ARGS args{};

        args.hIdentity = hIdentity->hIdentitySrv;
        if (lpCredType != nullptr)
            wcsncpy(args.szCredType, lpCredType, 64);
        else
            memset(args.szCredType, 0, 64 * sizeof(WCHAR));

        HRESULT hr = S_OK;
        if (FAILED(hr = DeviceIoControl(g_hDriver,
                                        IOCTL_WLIDSVC_PERSIST_CREDENTIAL,
                                        &args, sizeof(IOCTL_PERSIST_CREDENTIAL_ARGS),
                                        NULL, 0,
                                        NULL, NULL)))
            return hr;

        return hr;
    }

    HRESULT RemovePersistedCredential(IN HIDENTITY hIdentity, IN LPCWSTR lpCredType)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("[E_NOTIMPL] RemovePersistedCredential: hIdentity=%08hx; lpCredType=%s;"), hIdentity, LOG_STRING(lpCredType));
        return E_NOTIMPL;
    }

    HRESULT WINAPI SetCredential(IN HIDENTITY hIdentity, IN LPCWSTR szCredType, IN LPCWSTR szCredValue)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("SetCredential: hIdentity=%08hx; szCredType=%s; szCredValue=REDACTED;"), hIdentity, LOG_STRING(szCredType));

        if (hIdentity == nullptr || szCredType == nullptr || szCredValue == nullptr)
        {
            return E_INVALIDARG;
        }

        IOCTL_SET_CREDENTIAL_ARGS args{};
        args.hIdentity = hIdentity->hIdentitySrv;
        wcsncpy(args.szCredentialType, szCredType, 64);
        wcsncpy(args.szCredential, szCredValue, 256);

        HRESULT hr = S_OK;
        if (FAILED(hr = DeviceIoControl(g_hDriver,
                                        IOCTL_WLIDSVC_SET_CREDENTIAL,
                                        &args, sizeof(IOCTL_SET_CREDENTIAL_ARGS),
                                        NULL, 0,
                                        NULL, NULL)))
            return hr;

        return hr;
    }

    HRESULT SetExtendedProperty(IN LPCWSTR szPropertyName, IN LPCWSTR szPropertyValue)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("[E_NOTIMPL] SetExtendedProperty: szPropertyName=%s; szPropertyValue=%s;"), LOG_STRING(szPropertyName), LOG_STRING(szPropertyValue));
        return E_NOTIMPL;
    }

    HRESULT SetHIPSolution(IN LPVOID lpUnk1, IN LPCWSTR lpUnk2, IN LPCWSTR lpUnk3)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("[E_NOTIMPL] SetHIPSolution: lpUnk1=%08hx; lpUnk2=%s; lpUnk3=%s;"), lpUnk1, LOG_STRING(lpUnk2), LOG_STRING(lpUnk3));
        return E_NOTIMPL;
    }

    HRESULT SetIdentityProperty(
        IN HIDENTITY hIdentity,
        PPCRL_IDENTITY_PROPERTY Property,
        IN LPCWSTR szPropertyValue)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("SetIdentityProperty: hIdentity=%08hx; Property=%d, szPropertyValue=%s;"), hIdentity, Property, LOG_STRING(szPropertyValue));

        IOCTL_SET_IDENTITY_PROPERTY_ARGS args{};
        args.hIdentity = hIdentity->hIdentitySrv;
        args.dwProperty = Property;
        wcsncpy(args.szProperty, szPropertyValue, 256);

        HRESULT hr = S_OK;
        if (FAILED(hr = DeviceIoControl(g_hDriver,
                                        IOCTL_WLIDSVC_SET_IDENTITY_PROPERTY,
                                        &args, sizeof(IOCTL_SET_IDENTITY_PROPERTY_ARGS),
                                        NULL, 0,
                                        NULL, NULL)))
            return hr;

        return hr;
    }

    HRESULT SetLiveEnvironment(DWORD dwLiveEnvironment)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("[E_NOTIMPL] SetLiveEnvironment: dwLiveEnvironment=%d;"), dwLiveEnvironment);
        return E_NOTIMPL;
    }

    HRESULT SetUserExtendedProperty(
        IN LPCWSTR szUserName,
        IN LPCWSTR szPropertyName,
        IN LPCWSTR szPropertyValue)
    {
        critsect_t cs{&g_hDriverCrtiSec};

        LOG_MESSAGE_FMT(TEXT("[E_NOTIMPL] SetUserExtendedProperty: szUserName=%s; szPropertyName=%s, szPropertyValue=%s;"), LOG_STRING(szUserName), LOG_STRING(szPropertyName), LOG_STRING(szPropertyValue));
        return E_NOTIMPL;
    }

    HRESULT WSAccrueProfile(
        IN HIDENTITY hIdentity,
        DWORD dwUnk1,
        LPCWSTR szUnk2,
        int iUnk3)
    {
        critsect_t cs{&g_hDriverCrtiSec};
        LOG_MESSAGE(TEXT("[E_NOTIMPL] WSAccrueProfile"));

        return E_NOTIMPL;
    }

    HRESULT WSChangePassword(
        IN HIDENTITY hIdentity,
        IN LPCWSTR szUnk1,
        IN LPCWSTR szUnk2,
        DWORD dwUnk3)
    {
        critsect_t cs{&g_hDriverCrtiSec};
        LOG_MESSAGE(TEXT("[E_NOTIMPL] WSChangePassword"));

        return E_NOTIMPL;
    }

    HRESULT WSChangeSQSA(
        IN HIDENTITY hIdentity,
        IN LPCWSTR szUnk1,
        IN LPCWSTR szUnk2)
    {
        critsect_t cs{&g_hDriverCrtiSec};
        LOG_MESSAGE(TEXT("[E_NOTIMPL] WSChangeSQSA"));

        return E_NOTIMPL;
    }

    HRESULT WSGetHIPImage(
        IN LPCWSTR szUnk1,
        OUT LPWSTR *pwszUnk2,
        OUT LPWSTR *pwszUnk3)
    {
        critsect_t cs{&g_hDriverCrtiSec};
        LOG_MESSAGE(TEXT("[E_NOTIMPL] WSGetHIPImage"));

        return E_NOTIMPL;
    }

    HRESULT WSResolveHIP(IN LPVOID lpUnk1, IN HIDENTITY *hIdentity, LPCWSTR szUnk2)
    {
        critsect_t cs{&g_hDriverCrtiSec};
        LOG_MESSAGE(TEXT("[E_NOTIMPL] WSResolveHIP"));

        return E_NOTIMPL;
    }
}
