#pragma once
#include <windows.h>

extern "C"
{
    HRESULT GetDeviceUniqueID(
        LPBYTE pbApplicationData,
        DWORD cbApplictionData,
        DWORD dwDeviceIDVersion,
        LPBYTE pbDeviceIDOutput,
        DWORD *pcbDeviceIDOutput);
}

namespace wlidsvc::deviceid
{
    HRESULT GenerateProvisioningCertificateRequest(LPSTR *szCertRequest, DWORD *pcbCertRequest);
    HRESULT StoreProvisioningCertificate(LPCSTR szCertificate);
    HRESULT FetchDeviceCertificate();
}
