#pragma once
#include "windows.h"

typedef struct tag_RSTParams
{
    DWORD cbSize;
    LPWSTR szServiceTarget;
    LPWSTR szServicePolicy;
    DWORD dwTokenFlags;
    DWORD dwTokenParam;
} RSTParams, *LPRSTParams;

typedef struct tag_PIH
{
    DWORD_PTR hIdentitySrv;
} PIH, *PPIH;

typedef PIH *HIDENTITY;

typedef struct tag_PEIH
{

} PEIH, *PPEIH;

typedef PEIH *HENUMIDENTITY;

enum PPCRL_PASSWORD_STRENGTH
{
    PPCRL_PASSWORD_STRENGTH_NONE = 0,
    PPCRL_PASSWORD_STRENGTH_WEAK,
    PPCRL_PASSWORD_STRENGTH_MEDIUM,
    PPCRL_PASSWORD_STRENGTH_STRONG,
    PPCRL_FORCE_DWORD = 0xFFFFFFFF,
};

enum PPCRL_IDENTITY_PROPERTY
{
    IDENTITY_MEMBER_NAME = 1,
    IDENTITY_PUIDSTR,
    IDENTITY_FORCE_DWORD = 0xFFFFFFFF,
};

typedef struct tag_WLIDProperty
{

} WLIDProperty, *LPWLIDProperty;

typedef struct tag_UIParam
{
    DWORD dwUiFlag;
    HWND hwndParent;
    LPWSTR lpszCobrandingText;
    LPWSTR lpszAppName;
    LPWSTR lpszSignupText;
    LPWSTR lpszCobrandingLogoPath;
    LPWSTR lpszHeaderBgImage;
    DWORD dwBgColor;
    DWORD dwUrlColor;
    DWORD dwTileBgColor;
    DWORD dwTileBdColor;
    DWORD dwFieldBdColor;
    DWORD dwCheckboxLbColor;
    DWORD dwBtTxtColor;
    DWORD dwTileLbColor;
    int lWinLeft;
    int lWinTop;
    LPWSTR lpszSignupUrl;
} UIParam, *LPUIPARAM;

typedef struct tag_IDCRL_OPTION
{
    DWORD m_dwId;
    DWORD_PTR m_pValue;
    DWORD m_cbValue;
} IDCRL_OPTION;
