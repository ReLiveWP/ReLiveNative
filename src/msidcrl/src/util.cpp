#include "msidcrl.h"
#include "logging.h"

#include <assert.h>

using namespace msidcrl::globals;

extern "C"
{
    /**
     * Serializes a set of RSTParams into a file mapping.
     */
    HRESULT SerializeRSTParams(
        IN RSTParams *pParams, IN DWORD dwParamCount, OUT GUID *lpgFileName, OUT HANDLE *hMappedFile, OUT DWORD *dwFileSize)
    {
        *hMappedFile = NULL;
        *lpgFileName = GUID{0};
        if (dwParamCount == 0 || pParams == nullptr)
        {
            return S_FALSE;
        }

        DWORD cbSize = 8 + (sizeof(RSTParams) * dwParamCount);
        cbSize += (cbSize % 16);

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
        // *(DWORD *)pBuffer = cbSize;
        // *(DWORD *)(pBuffer + 4) = dwParamCount;

        DWORD *dwBuf = (DWORD *)pBuffer;
        dwBuf[0] = cbSize;
        dwBuf[1] = dwParamCount;

        DWORD_PTR offset = 8;
        DWORD_PTR initialOffset = 8;
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

        // round offset to the nearest 16 bytes
        offset += (offset % 16);

        // create a string table for the service targets and policies
        for (DWORD i = 0; i < dwParamCount; ++i)
        {
            if (pParams[i].szServiceTarget != nullptr)
            {
                auto len = (wcslen(pParams[i].szServiceTarget) + 1) * sizeof(WCHAR);
                memcpy((pBuffer + offset), pParams[i].szServiceTarget, len);

                RSTParams *pParam = (RSTParams *)(pBuffer + initialOffset + (sizeof(RSTParams) * i));
                pParam->szServiceTarget = (LPWSTR)offset;

                offset += len;
            }

            if (pParams[i].szServicePolicy != nullptr)
            {
                auto len = (wcslen(pParams[i].szServicePolicy) + 1) * sizeof(WCHAR);
                memcpy((pBuffer + offset), pParams[i].szServicePolicy, len);

                RSTParams *pParam = (RSTParams *)(pBuffer + initialOffset + (sizeof(RSTParams) * i));
                pParam->szServicePolicy = (LPWSTR)offset;

                offset += len;
            }
        }

        assert(offset == cbSize);

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
        *dwFileSize = cbSize;
        free(pBuffer);

        LOG_MESSAGE_FMT(TEXT("Serialized RSTParams to file: %s"), szGuid);
        return S_OK;
    }
}