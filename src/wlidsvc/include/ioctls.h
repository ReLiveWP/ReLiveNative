#pragma once
#include <windows.h>
#include "wlidcomm.h"
#include "types.h"

#define IOCTL_FUNC(Name) BOOL WLI_##Name(wlidsvc::handle_ctx_t *hContext, PBYTE pBufIn, DWORD dwLenIn, PBYTE pBufOut, DWORD dwLenOut, PDWORD pdwActualOut)

IOCTL_FUNC(HandleLogMessage);
IOCTL_FUNC(HandleLogMessageWide);

IOCTL_FUNC(InitHandle);
IOCTL_FUNC(GetDefaultID);

IOCTL_FUNC(CreateIdentityHandle);
IOCTL_FUNC(CloseIdentityHandle);