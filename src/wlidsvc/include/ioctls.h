#pragma once
#include <windows.h>
#include "wlidcomm.h"
#include "types.h"

#define IOCTL_FUNC(Name) BOOL WLI_##Name(wlidsvc::handle_ctx_t *hContext, PBYTE pBufIn, DWORD dwLenIn, PBYTE pBufOut, DWORD dwLenOut, PDWORD pdwActualOut)

IOCTL_FUNC(HandleLogMessage);
IOCTL_FUNC(HandleLogMessageWide);

IOCTL_FUNC(InitHandle);
IOCTL_FUNC(GetLiveEnvironment);
IOCTL_FUNC(GetDefaultID);

IOCTL_FUNC(CreateIdentityHandle);
IOCTL_FUNC(CloseIdentityHandle);

IOCTL_FUNC(GetIdentityPropertyByName);
IOCTL_FUNC(SetIdentityProperty);

IOCTL_FUNC(SetCredential);
IOCTL_FUNC(PersistCredential);
IOCTL_FUNC(GetAuthStateEx);

IOCTL_FUNC(AuthIdentityToService);
IOCTL_FUNC(AuthIdentityToServiceEx);
IOCTL_FUNC(LogonIdentityEx);

IOCTL_FUNC(EnumIdentitiesWithCachedCredentials);
IOCTL_FUNC(CloseEnumIdentitiesHandle);
