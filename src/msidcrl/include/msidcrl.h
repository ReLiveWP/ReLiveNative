#pragma once

#ifndef UNDER_CE
#define IS_TESTING 1
#endif

#include <windows.h>
#include <wincrypt.h>
#include <wlidcomm.h>

extern "C"
{
    
    HRESULT Initialize(GUID *lpGuid, DWORD dwVersionMajor, DWORD dwVersionMinor);
    HRESULT Uninitialize();
    HRESULT AuthIdentityToService(
        IN HIDENTITY hIdentity,
        IN LPCWSTR szServiceTarget,
        IN OPTIONAL LPCWSTR szServicePolicy,
        IN DWORD dwTokenRequestFlags,
        OUT OPTIONAL LPWSTR *szToken,
        OUT OPTIONAL DWORD *pdwResultFlags,
        OUT OPTIONAL BYTE **ppbSessionKey,
        OUT OPTIONAL DWORD *pcbSessionKeyLength);
    HRESULT AuthIdentityToServiceEx(
        IN HIDENTITY hIdentity,
        IN DWORD serviceTokenFlags,
        IN LPRSTParams pParams,
        IN DWORD dwParamCount);
    HRESULT CheckPasswordStrength(IN LPCWSTR szPassword, OUT PPCRL_PASSWORD_STRENGTH *pStrength);
    HRESULT CloseDeviceID(IN DWORD dwFlags, IN LPCWSTR szAdditionalParams);
    HRESULT CloseEnumIdentitiesHandle(IN HENUMIDENTITY hEnumIdentities);
    HRESULT CloseIdentityHandle(IN HIDENTITY hIdentity);
    HRESULT CreateIdentityHandle(
        IN LPCWSTR szMemberName,
        IN DWORD dwIdentityFlags,
        OUT HIDENTITY *phIdentity);
    HRESULT CreateIdentityHandleFromAuthState(
        IN LPCWSTR szAuthToken,
        IN DWORD dwTokenFlags,
        OUT HIDENTITY *phIdentity);
    HRESULT CreateLiveIDAccount(
        IN LPCWSTR szMemberName,
        IN LPCWSTR szPassword,
        IN WLIDProperty *pProperties,
        IN DWORD dwPropertyCount,
        OUT WLIDProperty **ppProperties,
        OUT DWORD *pdwPropertyCount);
    HRESULT EncryptWithSessionKey(
        IN HIDENTITY hIdentity,
        IN LPCWSTR szServiceName,
        IN DWORD algIdEncrypt,
        IN DWORD algIdHash,
        IN LPCWSTR pbPlainText,
        OUT BYTE **ppbCipherText,
        OUT DWORD *pcbCipherTextLength);
    HRESULT DecryptWithSessionKey(
        IN HIDENTITY hIdentity,
        IN LPCWSTR szServiceName,
        IN DWORD algIdEncryt,
        IN DWORD algIdHash,
        IN BYTE *pbCipherText,
        IN DWORD cbCipherText,
        OUT LPWSTR *ppbPlainText,
        OUT DWORD *pcbPlainTextLength);
    HRESULT EnumIdentitiesWithCachedCredentials(IN LPCWSTR szCredType, OUT HENUMIDENTITY *phEnumIdentities);
    HRESULT ExportAuthState(
        IN HIDENTITY hIdentity,
        IN DWORD dwFlags,
        OUT LPWSTR *szAuthToken);
    HRESULT GetAuthState(
        IN HIDENTITY hIdentity,
        OUT OPTIONAL DWORD *pdwAuthState,
        OUT OPTIONAL DWORD *pdwAuthRequired,
        OUT OPTIONAL DWORD *pdwRequestStatus,
        OUT OPTIONAL LPWSTR *szWebFlowUrl);
    HRESULT GetAuthStateEx(
        IN HIDENTITY hIdentity,
        IN LPCWSTR szServiceTarget,
        OUT OPTIONAL DWORD *pdwAuthState,
        OUT OPTIONAL DWORD *pdwAuthRequired,
        OUT OPTIONAL DWORD *pdwRequestStatus,
        OUT OPTIONAL LPWSTR *szWebFlowUrl);
    HRESULT GetDefaultID(OUT LPWSTR *szDefaultID);
    HRESULT GetDeviceId(
        IN DWORD dwFlags,
        IN LPCWSTR pvAdditionalParams,
        OUT LPWSTR *pwszDeviceId,
        OUT PCCERT_CONTEXT *didCertContext);
    HRESULT GetExtendedError(
        IN HIDENTITY hIdentity,
        OUT DWORD *pdwErrorCategory,
        OUT DWORD *pdwErrorCode,
        OUT LPWSTR *szErrorBlob);
    HRESULT GetExtendedProperty(
        IN LPCWSTR szPropertyName,
        OUT LPWSTR *szPropertyValue);
    HRESULT GetHIPChallenge(
        IN HIDENTITY hIdentity,
        IN LPCWSTR szUnknown1,
        OUT LPWSTR *szChallenge);
    HRESULT GetIdentityPropertyByName(
        IN HIDENTITY hIdentity,
        IN LPCWSTR szPropertyName,
        OUT LPWSTR *szPropertyValue);
    HRESULT GetLiveEnvironment(OUT DWORD *pdwEnvironment);
    HRESULT GetPassword(IN LPCWSTR szUnk1, OUT LPWSTR *pwszUnk2);
    HRESULT GetResponseForHttpChallenge(
        IN HIDENTITY hIdentity,
        IN DWORD dwAuthFlags,
        IN DWORD dwSSOFlags,
        IN UIParam *pcUIParam,
        IN LPCWSTR wszServiceTarget,
        IN LPCWSTR wszChallenge,
        OUT LPWSTR *pwszResponse);
    HRESULT GetUserExtendedProperty(IN LPCWSTR userName, IN LPCWSTR propertyName, OUT LPWSTR *propertyValue);
    HRESULT GetWebAuthUrlEx(
        IN HIDENTITY hIdentity,
        IN DWORD dwWebAuthFlag,
        IN OPTIONAL LPCWSTR szTargetServiceName,
        IN OPTIONAL LPCWSTR szServicePolicy,
        IN LPCWSTR szAdditionalPostParams,
        OUT LPWSTR *pwszWebAuthUrl,
        OUT LPWSTR *pwszPostData);
    HRESULT HasPersistedCredential(IN HIDENTITY hIdentity, IN LPCWSTR szCredType, OUT BOOL *bHasPersistentCred);
    HRESULT HasSetCredential(IN HIDENTITY hIdentity, OUT BOOL *bHasSetCred);
    HRESULT LogonIdentityEx(
        IN HIDENTITY hIdentity,
        OPTIONAL IN LPCWSTR szAuthPolicy,
        IN DWORD dwAuthFlags,
        IN RSTParams *pcRSTParams,
        IN DWORD dwpcRSTParamsCount);
    HRESULT NextIdentity(IN HENUMIDENTITY hEnum, OUT LPWSTR *pwszMemberName);
    HRESULT PassportFreeMemory(IN OUT void *o);
    HRESULT PersistCredential(IN HIDENTITY hIdentity, IN LPCWSTR lpCredType);
    HRESULT RemovePersistedCredential(IN HIDENTITY hIdentity, IN LPCWSTR lpCredType);
    HRESULT SetCredential(IN HIDENTITY hIdentity, IN LPCWSTR szCredType, IN LPCWSTR szCredValue);
    HRESULT SetExtendedProperty(IN LPCWSTR szPropertyName, IN LPCWSTR szPropertyValue);
    HRESULT SetHIPSolution(IN LPVOID lpUnk1, IN LPCWSTR lpUnk2, IN LPCWSTR lpUnk3);
    HRESULT SetIdentityProperty(
        IN HIDENTITY hIdentity,
        PPCRL_IDENTITY_PROPERTY Property,
        IN LPCWSTR szPropertyValue);
    HRESULT SetLiveEnvironment(DWORD dwLiveEnvironment);
    HRESULT SetUserExtendedProperty(
        IN LPCWSTR szUserName,
        IN LPCWSTR szPropertyName,
        IN LPCWSTR szPropertyValue);
    HRESULT WSAccrueProfile(
        IN HIDENTITY hIdentity,
        DWORD dwUnk1,
        LPCWSTR szUnk2,
        int iUnk3);
    HRESULT WSChangePassword(
        IN HIDENTITY hIdentity,
        IN LPCWSTR szUnk1,
        IN LPCWSTR szUnk2,
        DWORD dwUnk3);
    HRESULT WSChangeSQSA(
        IN HIDENTITY hIdentity,
        IN LPCWSTR szUnk1,
        IN LPCWSTR szUnk2);
    HRESULT WSGetHIPImage(
        IN LPCWSTR szUnk1,
        OUT LPWSTR *pwszUnk2,
        OUT LPWSTR *pwszUnk3);
    HRESULT WSResolveHIP(IN LPVOID lpUnk1, IN HIDENTITY *hIdentity, LPCWSTR szUnk2);

    HRESULT SerializeRSTParams(IN RSTParams *pParams, IN DWORD dwParamCount, OUT LPGUID lpgFileName, OUT HANDLE* hMappedFile, OUT DWORD *dwFileSize);
}

#if IS_TESTING
#define ActivateDevice(...)
#undef CreateFile
#define CreateFile CreateFile_TestHook
extern "C" HANDLE CreateFile_TestHook(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile);
#undef DeviceIoControl
#define DeviceIoControl DeviceIoControl_TestHook
extern "C" BOOL DeviceIoControl_TestHook(
    HANDLE hDevice,
    DWORD dwIoControlCode,
    LPVOID lpInBuffer,
    DWORD nInBufferSize,
    LPVOID lpOutBuffer,
    DWORD nOutBufferSize,
    LPDWORD lpBytesReturned,
    LPOVERLAPPED lpOverlapped);
#undef CloseHandle
#define CloseHandle CloseHandle_TestHook
extern "C" BOOL CloseHandle_TestHook(HANDLE hDevice);
#endif
