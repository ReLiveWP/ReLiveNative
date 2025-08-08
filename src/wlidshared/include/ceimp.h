#pragma once
// undocced CE permissions and impersonation functions :D

#include <windows.h>

// the super token - access to everything
#define TOKEN_SYSTEM ((HANDLE)0x2)

// flags for CeCreateToken
#define TF_OWNED_BY_KERNEL 1 // the token is owned by kernel - should only used by filesys or the handle
                             // created will not be freed on process exit

extern "C"
{
#if 0
#define CeCreateToken(LPVOID pTok, DWORD dwFlags) (0)
#define CeRevertToSelf(void) (TRUE)
#define CeAccessCheck(LPVOID pSecDesc, HANDLE hTok, DWORD dwAccess) (TRUE)
#define CePrivilegeCheck(HANDLE hTok, LPDWORD pPrivs, int nPrivs) (TRUE)
#define CeImpersonateToken(HANDLE hTok) (TRUE)
#define CeCreateTokenFromAccount(LPCWSTR pszAccountName) (0)
#define CeImpersonateCurrentProcess(void) (TRUE)
#define CeDuplicateToken(HANDLE hTok, DWORD dwFlags, PHANDLE phRet) (FALSE)
#define CePolicyCheckWithContext(HANDLE hTok, LPCWSTR pszAccountName, DWORD dwUnk1, DWORD dwUnk2, DWORD dwFlags, DWORD dwUnk3, DWORD dwUnk4) (TRUE)
#else
    HANDLE CeCreateToken(LPVOID pTok, DWORD dwFlags);
    BOOL CeRevertToSelf(void);
    BOOL CeAccessCheck(LPVOID pSecDesc, HANDLE hTok, DWORD dwAccess);
    BOOL CePrivilegeCheck(HANDLE hTok, LPDWORD pPrivs, int nPrivs);
    BOOL CeImpersonateToken(HANDLE hTok);
    HANDLE CeCreateTokenFromAccount(LPCWSTR pszAccountName);
    BOOL CeImpersonateCurrentProcess(void);
    BOOL CeDuplicateToken(HANDLE hTok, DWORD dwFlags, PHANDLE phRet);
    BOOL CePolicyCheckWithContext(HANDLE hTok, LPCWSTR pszAccountName, DWORD dwUnk1, DWORD dwUnk2, DWORD dwFlags, DWORD dwUnk3, DWORD dwUnk4);
#endif
}