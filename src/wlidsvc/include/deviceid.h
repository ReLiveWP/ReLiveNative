#pragma once
#include <windows.h>

#include <string>

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
    // HRESULT GenerateProvisioningCertificateRequest(LPSTR *szCertRequest, DWORD *pcbCertRequest);
    // HRESULT StoreProvisioningCertificate(LPCSTR szCertificate);
    // HRESULT FetchDeviceCertificate();

    HRESULT EnsureProvisionedAsync();
    HRESULT FindDeviceCert(BOOL bGenerateIfMissing, std::string &device_cert_thumb);
}
