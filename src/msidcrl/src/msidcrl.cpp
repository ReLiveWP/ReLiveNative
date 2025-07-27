
#include "msidcrl.h"

extern "C"
{
    HRESULT Initialize(GUID *lpGuid, DWORD dwVersionMajor, DWORD dwVersionMinor)
    {
        wchar_t data[200] = {0};

        GUID guid = *lpGuid;

        wsprintf(data, L"lpGuid={%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}, dwVersionMajor=%d, dwVersionMinor=%d",
               guid.Data1, guid.Data2, guid.Data3,
               guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
               guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7], dwVersionMajor, dwVersionMinor);

        MessageBox(NULL, data, L"msidcrl initialized", MB_OK);

        return S_OK;
    }

    HRESULT Uninitialize()
    {
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
        return E_NOTIMPL;
    }

    HRESULT AuthIdentityToServiceEx(
        IN HIDENTITY hIdentity,
        IN DWORD serviceTokenFlags,
        IN LPRSTParams pParams,
        IN DWORD dwParamCount)
    {
        return E_NOTIMPL;
    }

    HRESULT CheckPasswordStrength(IN LPCWSTR szPassword, OUT PPCRL_PASSWORD_STRENGTH *pStrength)
    {
        if (pStrength == nullptr || szPassword == nullptr)
        {
            return E_INVALIDARG;
        }

        return E_NOTIMPL;
    }

    HRESULT CloseDeviceID(IN DWORD dwFlags, IN LPCWSTR szAdditionalParams)
    {
        if (dwFlags == 0 && szAdditionalParams == nullptr)
        {
            // yeah this one's a lil odd, but this is what the original code does
            return E_NOTIMPL;
        }

        return E_INVALIDARG;
    }

    HRESULT CloseEnumIdentitiesHandle(IN HENUMIDENTITY hEnumIdentities)
    {
        if (hEnumIdentities == nullptr)
        {
            return E_INVALIDARG;
        }

        return E_NOTIMPL;
    }

    HRESULT CloseIdentityHandle(IN HIDENTITY hIdentity)
    {
        if (hIdentity == nullptr)
        {
            return E_INVALIDARG;
        }

        return E_NOTIMPL;
    }

    HRESULT CreateIdentityHandle(
        IN LPCWSTR szMemberName,
        IN DWORD dwIdentityFlags,
        OUT HIDENTITY *phIdentity)
    {
        if (phIdentity == nullptr || szMemberName == nullptr)
        {
            return E_INVALIDARG;
        }

        return E_NOTIMPL;
    }

    HRESULT CreateIdentityHandleFromAuthState(
        IN LPCWSTR szAuthToken,
        IN DWORD dwTokenFlags,
        OUT HIDENTITY *phIdentity)
    {
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
        return E_NOTIMPL;
    }

    HRESULT DecryptWithSessionKey(
        IN HIDENTITY hIdentity,
        IN LPCWSTR szServiceName,
        IN DWORD algIdEncryt,
        IN DWORD algIdHash,
        IN BYTE *pbCipherText,
        IN DWORD cbCipherText,
        OUT LPWSTR *ppbPlainText,
        OUT DWORD *pcbPlainTextLength)
    {
        return E_NOTIMPL;
    }

    HRESULT EnumIdentitiesWithCachedCredentials(IN LPCWSTR szCredType, OUT HENUMIDENTITY *phEnumIdentities)
    {
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
        if (hIdentity == nullptr || szAuthToken == nullptr)
        {
            return E_INVALIDARG;
        }

        return E_NOTIMPL;
    }

    HRESULT GetAuthState(
        IN HIDENTITY hIdentity,
        OUT DWORD *pdwAuthState,
        OUT DWORD *pdwAuthRequired,
        OUT DWORD *pdwRequestStatus,
        OUT LPWSTR *szWebFlowUrl)
    {
        if (hIdentity == nullptr || pdwAuthState == nullptr || pdwAuthRequired == nullptr ||
            pdwRequestStatus == nullptr || szWebFlowUrl == nullptr)
        {
            return E_INVALIDARG;
        }

        return E_NOTIMPL;
    }

    HRESULT GetAuthStateEx(
        IN HIDENTITY hIdentity,
        IN LPCWSTR szServiceTarget,
        OUT DWORD *pdwAuthState,
        OUT DWORD *pdwAuthRequired,
        OUT DWORD *pdwRequestStatus,
        OUT LPWSTR *szWebFlowUrl)
    {
        if (hIdentity == nullptr || szServiceTarget == nullptr || pdwAuthState == nullptr ||
            pdwAuthRequired == nullptr || pdwRequestStatus == nullptr || szWebFlowUrl == nullptr)
        {
            return E_INVALIDARG;
        }

        return E_NOTIMPL;
    }

    HRESULT GetDefaultID(OUT LPWSTR *szDefaultID)
    {
        if (szDefaultID == nullptr)
        {
            return E_INVALIDARG;
        }

        *szDefaultID = nullptr;

        return E_NOTIMPL;
    }

    HRESULT GetDeviceId(
        IN DWORD dwFlags,
        IN LPCWSTR pvAdditionalParams,
        OUT LPWSTR *pwszDeviceId,
        OUT PCCERT_CONTEXT *didCertContext)
    {
        return E_NOTIMPL;
    }

    HRESULT GetExtendedError(
        IN HIDENTITY hIdentity,
        OUT DWORD *pdwErrorCategory,
        OUT DWORD *pdwErrorCode,
        OUT LPWSTR *szErrorBlob)
    {
        if (hIdentity == nullptr || pdwErrorCategory == nullptr || pdwErrorCode == nullptr ||
            szErrorBlob == nullptr)
        {
            return E_INVALIDARG;
        }

        return E_NOTIMPL;
    }

    HRESULT GetExtendedProperty(
        IN HIDENTITY hIdentity,
        IN LPCWSTR szPropertyName,
        OUT LPWSTR *szPropertyValue)
    {
        if (hIdentity == nullptr || szPropertyName == nullptr || szPropertyValue == nullptr)
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
        if (hIdentity == nullptr || szPropertyName == nullptr || szPropertyValue == nullptr)
        {
            return E_INVALIDARG;
        }

        return E_NOTIMPL;
    }

    HRESULT GetLiveEnvironment(OUT DWORD *pdwEnvironment)
    {
        if (pdwEnvironment == nullptr)
        {
            return E_INVALIDARG;
        }

        *pdwEnvironment = 0; // Default to production environment

        return S_OK;
    }

    HRESULT GetPassword(IN LPCWSTR szUnk1, OUT LPWSTR *pwszUnk2)
    {
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
        if (hIdentity == nullptr || wszServiceTarget == nullptr || wszChallenge == nullptr ||
            pwszResponse == nullptr)
        {
            return E_INVALIDARG;
        }

        return E_NOTIMPL;
    }

    HRESULT GetUserExtendedProperty(IN LPCWSTR userName, IN LPCWSTR propertyName, OUT LPWSTR *propertyValue)
    {
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
        return E_NOTIMPL;
    }

    HRESULT HasPersistedCredential(IN HIDENTITY hIdentity, IN LPCWSTR szCredType, OUT BOOL *bHasPersistentCred)
    {
        return E_NOTIMPL;
    }

    HRESULT HasSetCredential(IN HIDENTITY hIdentity, OUT BOOL *bHasSetCred)
    {
        return E_NOTIMPL;
    }

    HRESULT LogonIdentityEx(
        IN HIDENTITY hIdentity,
        OPTIONAL IN LPCWSTR szAuthPolicy,
        IN DWORD dwAuthFlags,
        IN RSTParams *pcRSTParams,
        IN DWORD dwpcRSTParamsCount)
    {
        return E_NOTIMPL;
    }

    HRESULT NextIdentity(IN HENUMIDENTITY hEnum, OUT LPWSTR *pwszMemberName)
    {
        return E_NOTIMPL;
    }

    HRESULT PassportFreeMemory(IN OUT void *o)
    {
        free(o);
        return S_OK;
    }

    HRESULT PersistCredential(IN HIDENTITY hIdentity, IN LPCWSTR lpCredType)
    {
        return E_NOTIMPL;
    }

    HRESULT RemovePersistedCredential(IN HIDENTITY hIdentity, IN LPCWSTR lpCredType)
    {
        return E_NOTIMPL;
    }

    HRESULT SetCredential(IN HIDENTITY hIdentity, IN LPCWSTR szCredType, IN LPCWSTR szCredValue)
    {
        return E_NOTIMPL;
    }

    HRESULT SetExtendedProperty(IN LPCWSTR szPropertyName, IN LPCWSTR szPropertyValue)
    {
        return E_NOTIMPL;
    }

    HRESULT SetHIPSolution(IN LPVOID lpUnk1, IN LPCWSTR lpUnk2, IN LPCWSTR lpUnk3)
    {
        return E_NOTIMPL;
    }

    HRESULT SetIdentityProperty(
        IN HIDENTITY hIdentity,
        PPCRL_IDENTITY_PROPERTY Property,
        IN LPCWSTR szPropertyValue)
    {
        return E_NOTIMPL;
    }

    HRESULT SetLiveEnvironment(DWORD dwLiveEnvironment)
    {
        return E_NOTIMPL;
    }

    HRESULT SetUserExtendedProperty(
        IN LPCWSTR szUserName,
        IN LPCWSTR szPropertyName,
        IN LPCWSTR szPropertyValue)
    {
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
