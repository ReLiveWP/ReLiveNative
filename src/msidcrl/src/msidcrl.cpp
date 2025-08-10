
#include "msidcrl.h"
#include "logging.h"
#include "wlidcomm.h"

using namespace msidcrl::globals;

extern "C"
{
    HRESULT Initialize(GUID *lpGuid, DWORD dwVersionMajor, DWORD dwVersionMinor)
    {
        IOCTL_INIT_HANDLE_ARGS args = {};
        HANDLE hEvent, hDriver;
        HRESULT hr = S_OK;

        if (g_hDriver != NULL)
            return S_OK;

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

    HRESULT Uninitialize()
    {
        LOG_MESSAGE(TEXT("Uninitialize"));

        EnterCriticalSection(&g_hDriverCrtiSec);

        if (g_hDriver)
        {
            CloseHandle(g_hDriver);
            g_hDriver = NULL;
        }

        LeaveCriticalSection(&g_hDriverCrtiSec);

        return S_OK;
    }

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
        LOG_MESSAGE_FMT(
            TEXT("AuthIdentityToService: hIdentity=%08hx; szServiceTarget=%s; szServicePolicy=%s; dwTokenRequestFlags=%d;"),
            hIdentity, LOG_STRING(szServiceTarget), LOG_STRING(szServicePolicy), dwTokenRequestFlags);

        return E_NOTIMPL;
    }

    HRESULT AuthIdentityToServiceEx(
        IN HIDENTITY hIdentity,
        IN DWORD serviceTokenFlags,
        IN LPRSTParams pParams,
        IN DWORD dwParamCount)
    {
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
        LOG_MESSAGE_FMT(TEXT("CheckPasswordStrength: dwFlags=%s;"), TEXT("REDACTED"));

        if (pStrength == nullptr || szPassword == nullptr)
        {
            return E_INVALIDARG;
        }

        return E_NOTIMPL;
    }

    HRESULT CloseDeviceID(IN DWORD dwFlags, IN LPCWSTR szAdditionalParams)
    {
        LOG_MESSAGE_FMT(TEXT("CloseDeviceID: dwFlags=%d; szAdditionalParams=%s;"), dwFlags, LOG_STRING(szAdditionalParams));

        if (dwFlags == 0 && szAdditionalParams == nullptr)
        {
            // yeah this one's a lil odd, but this is what the original code does
            return E_NOTIMPL;
        }

        return E_INVALIDARG;
    }

    HRESULT CloseEnumIdentitiesHandle(IN HENUMIDENTITY hEnumIdentities)
    {
        LOG_MESSAGE_FMT(TEXT("CloseEnumIdentitiesHandle: hEnumIdentities=%08hx;"), hEnumIdentities);

        if (hEnumIdentities == nullptr)
        {
            return E_INVALIDARG;
        }

        return E_NOTIMPL;
    }

    HRESULT CloseIdentityHandle(IN HIDENTITY hIdentity)
    {
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

        return hr;
    }

    HRESULT CreateIdentityHandle(
        IN LPCWSTR szMemberName,
        IN DWORD dwIdentityFlags,
        OUT HIDENTITY *phIdentity)
    {
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

        PPIH hIdentity = (PPIH)malloc(sizeof(PIH));
        if (hIdentity == NULL)
            return E_OUTOFMEMORY;

        hIdentity->hIdentitySrv = retVal.hIdentity;

        *phIdentity = hIdentity;

        return hr;
    }

    HRESULT CreateIdentityHandleFromAuthState(
        IN LPCWSTR szAuthToken,
        IN DWORD dwTokenFlags,
        OUT HIDENTITY *phIdentity)
    {
        LOG_MESSAGE_FMT(TEXT("CreateIdentityHandle: szAuthToken=%s; dwTokenFlags=%d;"), LOG_STRING(szAuthToken), dwTokenFlags);

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
        LOG_MESSAGE_FMT(
            TEXT("CreateLiveIDAccount: szMemberName=%s; szPassword=%s; pProperties=%08hx; dwPropertyCount=%d;"),
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
        LOG_MESSAGE_FMT(
            TEXT("EncryptWithSessionKey: hIdentity=%08hx; szServiceName=%s; algIdEncrypt=%d, algIdHash=%d; pbPlainText=%s;"),
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
        LOG_MESSAGE_FMT(
            TEXT("DecryptWithSessionKey: hIdentity=%08hx; szServiceName=%s; algIdEncrypt=%d, algIdHash=%d;"),
            hIdentity,
            LOG_STRING(szServiceName),
            algIdEncrypt,
            algIdHash);

        return E_NOTIMPL;
    }

    HRESULT EnumIdentitiesWithCachedCredentials(IN LPCWSTR szCredType, OUT HENUMIDENTITY *phEnumIdentities)
    {
        LOG_MESSAGE_FMT(TEXT("EnumIdentitiesWithCachedCredentials: szCredType=%s;"), LOG_STRING(szCredType));

        if (phEnumIdentities == nullptr || szCredType == nullptr)
        {
            return E_INVALIDARG;
        }

        return E_NOTIMPL;
    }

    HRESULT ExportAuthState(
        IN HIDENTITY hIdentity,
        IN DWORD dwFlags,
        OUT LPWSTR *szAuthToken)
    {
        LOG_MESSAGE_FMT(TEXT("ExportAuthState: hIdentity=%08hx; dwFlags=%d;"), hIdentity, dwFlags);

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
                LPWSTR pszWebFlowUrl = (LPWSTR)malloc((len + 1) * sizeof(WCHAR));
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

        return hr;
    }

    HRESULT GetDefaultID(OUT LPWSTR *szDefaultID)
    {
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
        *szDefaultID = (LPWSTR)malloc(len * sizeof(WCHAR));
        wcsncpy(*szDefaultID, sData.szDefaultId, len);

        return hr;
    }

    HRESULT GetDeviceId(
        IN DWORD dwFlags,
        IN LPCWSTR pvAdditionalParams,
        OUT LPWSTR *pwszDeviceId,
        OUT PCCERT_CONTEXT *didCertContext)
    {
        LOG_MESSAGE_FMT(TEXT("GetDeviceId: dwFlags=%d; pvAdditionalParams=%s;"), dwFlags, LOG_STRING(pvAdditionalParams));

        return E_NOTIMPL;
    }

    HRESULT GetExtendedError(
        IN HIDENTITY hIdentity,
        OUT DWORD *pdwErrorCategory,
        OUT DWORD *pdwErrorCode,
        OUT LPWSTR *szErrorBlob)
    {
        LOG_MESSAGE_FMT(TEXT("GetExtendedError: hIdentity=%08hx;"), hIdentity);

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
        LOG_MESSAGE_FMT(TEXT("GetExtendedProperty: szPropertyName=%s;"), LOG_STRING(szPropertyName));

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
        LOG_MESSAGE_FMT(TEXT("GetHIPChallenge: hIdentity=%08hx; szUnknown1=%s;"), hIdentity, LOG_STRING(szUnknown1));

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
        else
            memset(args.szPropertyName, 0, 128 * sizeof(WCHAR));

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

        *szPropertyValue = (LPWSTR)malloc((len + 1) * sizeof(WCHAR));
        if (*szPropertyValue == nullptr)
            return E_OUTOFMEMORY;

        wcsncpy(*szPropertyValue, retVal.szPropertyValue, len + 1);
        (*szPropertyValue)[len] = L'\0';

        return E_NOTIMPL;
    }

    HRESULT GetLiveEnvironment(OUT DWORD *pdwEnvironment)
    {
        LOG_MESSAGE(TEXT("GetLiveEnvironment"));
        if (pdwEnvironment == nullptr)
        {
            return E_INVALIDARG;
        }

        HRESULT hr = S_OK;
        IOCTL_GET_LIVE_ENVIRONMENT_RETURN retVal{};
        if (FAILED(hr = DeviceIoControl(g_hDriver,
                                        IOCTL_WLIDSVC_GET_LIVE_ENVIRONMENT,
                                        NULL, 0,
                                        &retVal, sizeof(IOCTL_GET_LIVE_ENVIRONMENT_RETURN),
                                        NULL, NULL)))
            return hr;

        *pdwEnvironment = retVal.dwLiveEnv;

        return S_OK;
    }

    HRESULT GetPassword(IN LPCWSTR szUnk1, OUT LPWSTR *pwszUnk2)
    {
        LOG_MESSAGE_FMT(TEXT("GetPassword: szUnk1=%s;"), LOG_STRING(szUnk1));

        if (szUnk1 == nullptr || pwszUnk2 == nullptr)
        {
            return E_INVALIDARG;
        }

        return E_NOTIMPL;
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
        LOG_MESSAGE_FMT(TEXT("GetResponseForHttpChallenge: hIdentity=%08hx; dwAuthFlags=%d; dwSSOFlags=%d; pcUIParam=%08hx; wszServiceTarget=%s; wszChallenge=%s;"),
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
        LOG_MESSAGE_FMT(TEXT("GetUserExtendedProperty: userName=%s; propertyName=%s;"), LOG_STRING(userName), LOG_STRING(propertyName));

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
        LOG_MESSAGE_FMT(TEXT("GetWebAuthUrlEx: hIdentity=%08hx; dwWebAuthFlag=%d; szTargetServiceName=%s; szServicePolicy=%s; szAdditionalPostParams=%s;"),
                        hIdentity,
                        dwWebAuthFlag,
                        LOG_STRING(szTargetServiceName),
                        LOG_STRING(szServicePolicy),
                        LOG_STRING(szAdditionalPostParams));

        return E_NOTIMPL;
    }

    HRESULT HasPersistedCredential(IN HIDENTITY hIdentity, IN LPCWSTR szCredType, OUT BOOL *bHasPersistentCred)
    {
        LOG_MESSAGE_FMT(TEXT("HasPersistedCredential: hIdentity=%08hx; szCredType=%s;"),
                        hIdentity,
                        LOG_STRING(szCredType));
        return E_NOTIMPL;
    }

    HRESULT HasSetCredential(IN HIDENTITY hIdentity, OUT BOOL *bHasSetCred)
    {
        LOG_MESSAGE_FMT(TEXT("HasPersistedCredential: hIdentity=%08hx;"), hIdentity);
        return E_NOTIMPL;
    }

    HRESULT LogonIdentityEx(
        IN HIDENTITY hIdentity,
        OPTIONAL IN LPCWSTR szAuthPolicy,
        IN DWORD dwAuthFlags,
        IN OPTIONAL RSTParams *pcRSTParams,
        IN OPTIONAL DWORD dwpcRSTParamsCount)
    {
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
        else
            memset(args.szAuthPolicy, 0, 256 * sizeof(WCHAR));

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

    HRESULT NextIdentity(IN HENUMIDENTITY hEnum, OUT LPWSTR *pwszMemberName)
    {
        LOG_MESSAGE_FMT(TEXT("NextIdentity: hEnum=%08hx;"), hEnum);

        return E_NOTIMPL;
    }

    HRESULT PassportFreeMemory(IN OUT void *o)
    {
        free(o);
        return S_OK;
    }

    HRESULT PersistCredential(IN HIDENTITY hIdentity, IN LPCWSTR lpCredType)
    {
        LOG_MESSAGE_FMT(TEXT("PersistCredential: hIdentity=%08hx; lpCredType=%s;"), hIdentity, LOG_STRING(lpCredType));
        return E_NOTIMPL;
    }

    HRESULT RemovePersistedCredential(IN HIDENTITY hIdentity, IN LPCWSTR lpCredType)
    {
        LOG_MESSAGE_FMT(TEXT("RemovePersistedCredential: hIdentity=%08hx; lpCredType=%s;"), hIdentity, LOG_STRING(lpCredType));
        return E_NOTIMPL;
    }

    HRESULT SetCredential(IN HIDENTITY hIdentity, IN LPCWSTR szCredType, IN LPCWSTR szCredValue)
    {
        LOG_MESSAGE_FMT(TEXT("SetCredential: hIdentity=%08hx; szCredType=%s; szCredValue=%s;"), hIdentity, LOG_STRING(szCredType), LOG_STRING(szCredValue));

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
        LOG_MESSAGE_FMT(TEXT("SetExtendedProperty: szPropertyName=%s; szPropertyValue=%s;"), LOG_STRING(szPropertyName), LOG_STRING(szPropertyValue));
        return E_NOTIMPL;
    }

    HRESULT SetHIPSolution(IN LPVOID lpUnk1, IN LPCWSTR lpUnk2, IN LPCWSTR lpUnk3)
    {
        LOG_MESSAGE_FMT(TEXT("SetHIPSolution: lpUnk1=%08hx; lpUnk2=%s; lpUnk3=%s;"), lpUnk1, LOG_STRING(lpUnk2), LOG_STRING(lpUnk3));
        return E_NOTIMPL;
    }

    HRESULT SetIdentityProperty(
        IN HIDENTITY hIdentity,
        PPCRL_IDENTITY_PROPERTY Property,
        IN LPCWSTR szPropertyValue)
    {
        LOG_MESSAGE_FMT(TEXT("SetIdentityProperty: hIdentity=%08hx; Property=%d, szPropertyValue=%s;"), hIdentity, Property, LOG_STRING(szPropertyValue));
        return E_NOTIMPL;
    }

    HRESULT SetLiveEnvironment(DWORD dwLiveEnvironment)
    {
        LOG_MESSAGE_FMT(TEXT("SetLiveEnvironment: dwLiveEnvironment=%d;"), dwLiveEnvironment);
        return E_NOTIMPL;
    }

    HRESULT SetUserExtendedProperty(
        IN LPCWSTR szUserName,
        IN LPCWSTR szPropertyName,
        IN LPCWSTR szPropertyValue)
    {
        LOG_MESSAGE_FMT(TEXT("SetIdentityProperty: szUserName=%s; szPropertyName=%s, szPropertyValue=%s;"), LOG_STRING(szUserName), LOG_STRING(szPropertyName), LOG_STRING(szPropertyValue));
        return E_NOTIMPL;
    }

    HRESULT WSAccrueProfile(
        IN HIDENTITY hIdentity,
        DWORD dwUnk1,
        LPCWSTR szUnk2,
        int iUnk3)
    {
        return E_NOTIMPL;
    }

    HRESULT WSChangePassword(
        IN HIDENTITY hIdentity,
        IN LPCWSTR szUnk1,
        IN LPCWSTR szUnk2,
        DWORD dwUnk3)
    {
        return E_NOTIMPL;
    }

    HRESULT WSChangeSQSA(
        IN HIDENTITY hIdentity,
        IN LPCWSTR szUnk1,
        IN LPCWSTR szUnk2)
    {
        return E_NOTIMPL;
    }

    HRESULT WSGetHIPImage(
        IN LPCWSTR szUnk1,
        OUT LPWSTR *pwszUnk2,
        OUT LPWSTR *pwszUnk3)
    {
        return E_NOTIMPL;
    }

    HRESULT WSResolveHIP(IN LPVOID lpUnk1, IN HIDENTITY *hIdentity, LPCWSTR szUnk2)
    {
        return E_NOTIMPL;
    }
}
