#pragma once

#include <windows.h>

#define WLIDSVC_READY_EVENT TEXT("/GLOBAL/WLIDSVCREADY")
#define WLIDSVC_FILE TEXT("WLI1:")
#define WLIDSVC_NAME TEXT("WLIDSVC")

#define FORMAT_GUID TEXT("{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}")
#define PRINT_GUID(guid) (guid).Data1, (guid).Data2, (guid).Data3, (guid).Data4[0], (guid).Data4[1], (guid).Data4[2], (guid).Data4[3], (guid).Data4[4], (guid).Data4[5], (guid).Data4[6], (guid).Data4[7]

#define STRINGIZE(x) STRINGIZE2(x)
#define STRINGIZE2(x) #x

#define WLIDSVC_API_LEVEL 2

#define FACILITY_WLIDSVC 82
#define E_NOCURL MAKE_HRESULT(1, FACILITY_WLIDSVC, 1)
#define E_NOSQLITE MAKE_HRESULT(1, FACILITY_WLIDSVC, 2)

#define PPCRL_E_NO_MEMBER_NAME_SET 0x8004886c

//
// Macro definition for defining IOCTL and FSCTL function control codes.  Note
// that function codes 0-2047 are reserved for Microsoft Corporation, and
// 2048-4095 are reserved for customers.
//
#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) ( \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif
//
// Define the method codes for how buffers are passed for I/O and FS controls
//

#define METHOD_BUFFERED 0
#define METHOD_IN_DIRECT 1
#define METHOD_OUT_DIRECT 2
#define METHOD_NEITHER 3

//
// Define the access check value for any access
//
//
// The FILE_READ_ACCESS and FILE_WRITE_ACCESS constants are also defined in
// ntioapi.h as FILE_READ_DATA and FILE_WRITE_DATA. The values for these
// constants *MUST* always be in sync.
//

#define FILE_ANY_ACCESS 0
#define FILE_READ_ACCESS (0x0001)  // file & pipe
#define FILE_WRITE_ACCESS (0x0002) // file & pipe

#define FILE_DEVICE_UNKNOWN 0x00000022

#define BEGIN_IOCTL_MAP() \
    HRESULT __imp_hr;     \
    switch (dwCode)       \
    {

#define IOCTL_HANDLER_NO_LOG(code, handler) \
    case code:                              \
        return handler((wlidsvc::handle_ctx_t *)hContext, pBufIn, dwLenIn, pBufOut, dwLenOut, pdwActualOut);

#define IOCTL_HANDLER(code, handler)                                                                             \
    case code:                                                                                                   \
        LOG("[0x%08x] IOCTL[%s]", hContext, STRINGIZE(handler));                                                 \
        __imp_hr = handler((wlidsvc::handle_ctx_t *)hContext, pBufIn, dwLenIn, pBufOut, dwLenOut, pdwActualOut); \
        LOG("[0x%08x] IOCTL[%s] 0x%08x", hContext, STRINGIZE(handler), __imp_hr);                                \
        return __imp_hr;

#define END_IOCTL_MAP()                       \
    default:                                  \
        SetLastError(ERROR_INVALID_FUNCTION); \
        return FALSE;                         \
        }

#pragma pack(push, 1)

#include "msidcrlstr.h"

#define IOCTL_WLIDSVC_LOG_MESSAGE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WLIDSVC_LOG_MESSAGE_WIDE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct
{
    DWORD dwApiLevel;
    GUID gApp;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    WCHAR szExecutable[MAX_PATH];
} IOCTL_INIT_HANDLE_ARGS, *PIOCTL_INIT_HANDLE_ARGS;

#define IOCTL_WLIDSVC_INIT_HANDLE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct
{
    WCHAR szDefaultId[256];
} IOCTL_GET_DEFAULT_ID_RETURN, *PIOCTL_GET_DEFAULT_ID_RETURN;

#define IOCTL_WLIDSVC_GET_DEFAULT_ID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct
{
    WCHAR szMemberName[128];
    DWORD dwIdentityFlags;
} IOCTL_CREATE_IDENTITY_HANDLE_ARGS, *PIOCTL_CREATE_IDENTITY_HANDLE_ARGS;

typedef struct
{
    DWORD_PTR hIdentity;
} IOCTL_CREATE_IDENTITY_HANDLE_RETURN, *PIOCTL_CREATE_IDENTITY_HANDLE_RETURN;

#define IOCTL_WLIDSVC_CREATE_IDENTITY_HANDLE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct
{
    DWORD_PTR hIdentity;
} IOCTL_CLOSE_IDENTITY_HANDLE_ARGS, *PIOCTL_CLOSE_IDENTITY_HANDLE_ARGS;

#define IOCTL_WLIDSVC_CLOSE_IDENTITY_HANDLE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct
{
    DWORD dwLiveEnv;
} IOCTL_GET_LIVE_ENVIRONMENT_RETURN, *PIOCTL_GET_LIVE_ENVIRONMENT_RETURN;
#define IOCTL_WLIDSVC_GET_LIVE_ENVIRONMENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct
{
    DWORD_PTR hIdentity;
    WCHAR szPropertyName[128];
} IOCTL_GET_IDENTITY_PROPERTY_BY_NAME_ARGS, *PIOCTL_GET_IDENTITY_PROPERTY_BY_NAME_ARGS;

typedef struct
{
    WCHAR szPropertyValue[128];
} IOCTL_GET_IDENTITY_PROPERTY_BY_NAME_RETURN, *PIOCTL_GET_IDENTITY_PROPERTY_BY_NAME_RETURN;
#define IOCTL_WLIDSVC_GET_IDENTITY_PROPERTY_BY_NAME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct
{
    DWORD_PTR hIdentity;
    WCHAR szCredentialType[64];
    WCHAR szCredential[256];
} IOCTL_SET_CREDENTIAL_ARGS, *PIOCTL_SET_CREDENTIAL_ARGS;
#define IOCTL_WLIDSVC_SET_CREDENTIAL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)

// GetAuthStateEx
typedef struct
{
    DWORD_PTR hIdentity;
    WCHAR szServiceTarget[256];
} IOCTL_GET_AUTH_STATE_EX_ARGS, *PIOCTL_GET_AUTH_STATE_EX_ARGS;

typedef struct
{
    DWORD dwAuthState;
    DWORD dwAuthRequired;
    DWORD dwRequestStatus;
    WCHAR szWebFlowUrl[512];
} IOCTL_GET_AUTH_STATE_EX_RETURN, *PIOCTL_GET_AUTH_STATE_EX_RETURN;

#define IOCTL_WLIDSVC_GET_AUTH_STATE_EX CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct
{
    DWORD_PTR hIdentity;
    DWORD dwServiceTokenFlags;
    GUID gMapParams;
    DWORD dwParamCount;
} IOCTL_AUTH_IDENTITY_TO_SERVICE_EX_ARGS, *PIOCTL_AUTH_IDENTITY_TO_SERVICE_EX_ARGS;

#define IOCTL_WLIDSVC_AUTH_IDENTITY_TO_SERVICE_EX CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct
{
    DWORD_PTR hIdentity;
    WCHAR szAuthPolicy[256];
    DWORD dwAuthFlags;
    GUID gMapParams;
    DWORD dwParamCount;
} IOCTL_LOGON_IDENTITY_EX_ARGS, *PIOCTL_LOGON_IDENTITY_EX_ARGS;

#define IOCTL_WLIDSVC_LOGON_IDENTITY_EX CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(pop)