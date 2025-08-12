#pragma once
#include <windef.h>
#include <msidcrlstr.h>


typedef struct tag_ENUM_IDENTITY_CREDENTIALS_ITEM
{
    LPWSTR szIdentity;
    tag_ENUM_IDENTITY_CREDENTIALS_ITEM *next;
} ENUM_IDENTITY_CREDENTIALS_ITEM, *PENUM_IDENTITY_CREDENTIALS_ITEM;

typedef struct tag_ENUM_IDENTITY_CREDENTIALS
{
    HANDLE hMap;
    BYTE *pMapView;
    DWORD_PTR hServerHandle;
    tag_ENUM_IDENTITY_CREDENTIALS_ITEM *root;
    tag_ENUM_IDENTITY_CREDENTIALS_ITEM *current;
} ENUM_IDENTITY_CREDENTIALS, *PENUM_IDENTITY_CREDENTIALS;

extern "C"
{
    HRESULT SerializeRSTParams(IN RSTParams *pParams, IN DWORD dwParamCount, OUT LPGUID lpgFileName, OUT HANDLE *hMappedFile, OUT DWORD *dwFileSize);
    HRESULT Server_CloseEnumIdentitiesHandle(IN DWORD_PTR hEnumServer);
}