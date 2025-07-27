#pragma once
#include <windows.h>
#include "wlidcomm.h"

BOOL WLI_HandleLogMessage(DWORD hContext, PBYTE pBufIn, DWORD dwLenIn, PBYTE pBufOut, DWORD dwLenOut, PDWORD pdwActualOut);
BOOL WLI_HandleLogMessageWide(DWORD hContext, PBYTE pBufIn, DWORD dwLenIn, PBYTE pBufOut, DWORD dwLenOut, PDWORD pdwActualOut);