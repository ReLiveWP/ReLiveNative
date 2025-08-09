#include "msidcrl.h"
#include "logging.h"

using namespace msidcrl::globals;

extern "C"
{
    /**
     * Serializes a set of RSTParams into a file mapping.
     */
    HRESULT SerializeRSTParams(IN RSTParams *pParams, IN DWORD dwParamCount, OUT GUID* lpgFileName, OUT HANDLE* hMappedFile)
    {
        *hMappedFile = NULL;
        *lpgFileName = GUID{0};
        if (dwParamCount == 0 || pParams == nullptr)
        {
            return S_FALSE;
        }

        DWORD cbSize = 8 + sizeof(RSTParams) * dwParamCount;
        for (DWORD i = 0; i < dwParamCount; ++i)
        {
            if (pParams[i].szServiceTarget != nullptr)
                cbSize += (wcslen(pParams[i].szServiceTarget) + 1) * sizeof(WCHAR);
            if (pParams[i].szServicePolicy != nullptr)
                cbSize += (wcslen(pParams[i].szServicePolicy) + 1) * sizeof(WCHAR);
        }

        BYTE *pBuffer = (BYTE *)calloc(cbSize, sizeof(BYTE));
        if (pBuffer == nullptr)
            return E_OUTOFMEMORY;

        // first 4 bytes are the total size, next 4 bytes are the parameter count
        *(DWORD *)pBuffer = cbSize;
        *(DWORD *)(pBuffer + 4) = dwParamCount;

        DWORD offset = 8;
        for (DWORD i = 0; i < dwParamCount; ++i)
        {
            RSTParams *pParam = reinterpret_cast<RSTParams *>(pBuffer + offset);
            pParam->cbSize = sizeof(RSTParams);
            pParam->dwTokenFlags = pParams[i].dwTokenFlags;
            pParam->dwTokenParam = pParams[i].dwTokenParam;
            pParam->szServiceTarget = NULL; // will be set later
            pParam->szServicePolicy = NULL; // will be set later

            offset += sizeof(RSTParams);
        }

        // create a string table for the service targets and policies
        for (DWORD i = 0; i < dwParamCount; ++i)
        {
            RSTParams *pParam = reinterpret_cast<RSTParams *>(pBuffer + (sizeof(RSTParams) * i));

            if (pParams[i].szServiceTarget != nullptr)
            {
                pParam->szServiceTarget = reinterpret_cast<LPWSTR>(offset);
                wcscpy(reinterpret_cast<LPWSTR>(pBuffer + offset), pParams[i].szServiceTarget);
                offset += (wcslen(pParams[i].szServiceTarget) + 1) * sizeof(WCHAR);
            }

            if (pParams[i].szServicePolicy != nullptr)
            {
                pParam->szServicePolicy = reinterpret_cast<LPWSTR>(offset);
                wcscpy(reinterpret_cast<LPWSTR>(pBuffer + offset), pParams[i].szServicePolicy);
                offset += (wcslen(pParams[i].szServicePolicy) + 1) * sizeof(WCHAR);
            }
        }

        GUID guid = {0};
        CoCreateGuid(&guid);

        WCHAR szGuid[40] = {0};
        StringFromGUID2(guid, szGuid, 40);
        HANDLE hMap = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, cbSize, szGuid);
        if (hMap == NULL)
        {
            free(pBuffer);
            return HRESULT_FROM_WIN32(GetLastError());
        }

        BYTE *pMapView = (BYTE *)MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, cbSize);
        if (pMapView == NULL)
        {
            CloseHandle(hMap);
            free(pBuffer);
            return HRESULT_FROM_WIN32(GetLastError());
        }

        memcpy(pMapView, pBuffer, cbSize);
        UnmapViewOfFile(pMapView);

        *hMappedFile = hMap;
        *lpgFileName = guid;
        free(pBuffer);

        LOG_MESSAGE_FMT(TEXT("Serialized RSTParams to file: %s"), szGuid);
        return S_OK;
    }
}