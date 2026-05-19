#include "deviceid.h"
#include "log.h"
#include "util.h"
#include "config.h"
#include "storage.h"
#include "urls.h"
#include "microrest.h"

#include <string.h>
#include <malloc.h>

#include <ncrypt.h>
#include <wincrypt.h>
#include <string>
#include <base64.hpp>
#include <wlidcomm.h>

#include <cerrno>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

using namespace wlidsvc::config;
using namespace wlidsvc::storage;

extern "C"
{
#ifndef UNDER_CE
    HRESULT GetDeviceUniqueID(
        LPBYTE pbApplicationData,
        DWORD cbApplictionData,
        DWORD dwDeviceIDVersion,
        LPBYTE pbDeviceIDOutput,
        DWORD *pcbDeviceIDOutput)
    {
        const BYTE defaultId[20] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
        memcpy(pbDeviceIDOutput, defaultId, 20);
        *pcbDeviceIDOutput = 20;
        return S_OK;
    }
#endif
}

namespace wlidsvc::deviceid
{
    namespace cert
    {
        // long __thiscall CCertObject::GenerateCertKey(CCertObject *this,ulong param_1) @ 0x1004a3cc
        HRESULT GenerateCertKey(NCRYPT_PROV_HANDLE hProv, NCRYPT_KEY_HANDLE *pKeyOut)
        {
            /**
             *  Notes:
             *      - CONTAINER_NAME is actually sprintf("%s_%s", CONTAINER_NAME, UuidToString(UuidCreate())), we use a static one right now.
             */

            NCRYPT_KEY_HANDLE hKey = 0;
            SECURITY_STATUS status = 0;
            HRESULT hr = S_OK;
            DWORD keyLengthBits = 1024;
            DWORD needed;
            PBYTE buffer;

            status = NCryptCreatePersistedKey(hProv, &hKey, BCRYPT_RSA_ALGORITHM, TEXT(CONTAINER_NAME), 0, 0);

            // TODO: don't ship this <3
            if (status == NTE_EXISTS)
            {
                if ((status = NCryptOpenKey(hProv, &hKey, TEXT(CONTAINER_NAME), 0, 0)) != ERROR_SUCCESS)
                {
                    LOG("NCryptOpenKey failed 0x%08x;", status);
                    return HRESULT_FROM_WIN32(status);
                }
                NCryptDeleteKey(hKey, 0);

                status = NCryptCreatePersistedKey(hProv, &hKey, BCRYPT_RSA_ALGORITHM, TEXT(CONTAINER_NAME), 0, 0);
            }

            if (status != NTE_EXISTS)
            {
                if (status != ERROR_SUCCESS)
                {
                    LOG("NCryptCreatePersistedKey failed 0x%08x;", status);
                    return HRESULT_FROM_WIN32(status);
                }

                if ((status = NCryptSetProperty(hKey, NCRYPT_LENGTH_PROPERTY,
                                                (PBYTE)&keyLengthBits, sizeof(keyLengthBits), 0)) != ERROR_SUCCESS)
                {
                    LOG("NCryptSetProperty NCRYPT_LENGTH_PROPERTY failed 0x%08x;", status);
                    return HRESULT_FROM_WIN32(status);
                }

                DWORD exportPolicy = NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
                if ((status = NCryptSetProperty(hKey, NCRYPT_EXPORT_POLICY_PROPERTY,
                                                (PBYTE)&exportPolicy, sizeof(exportPolicy), 0)) != ERROR_SUCCESS)
                {
                    LOG("NCryptSetProperty NCRYPT_EXPORT_POLICY_PROPERTY failed 0x%08x;", status);
                    return HRESULT_FROM_WIN32(status);
                }

                DWORD keyUsage = NCRYPT_ALLOW_DECRYPT_FLAG | NCRYPT_ALLOW_SIGNING_FLAG;
                if ((status = NCryptSetProperty(hKey, NCRYPT_KEY_USAGE_PROPERTY,
                                                (PBYTE)&keyUsage, sizeof(keyUsage), 0)) != ERROR_SUCCESS)
                {
                    LOG("NCryptSetProperty NCRYPT_KEY_USAGE_PROPERTY failed 0x%08x;", status);
                    return HRESULT_FROM_WIN32(status);
                }

                if ((status = NCryptFinalizeKey(hKey, 0)) != ERROR_SUCCESS)
                {
                    LOG("NCryptFinalizeKey failed 0x%08x;", status);
                    return HRESULT_FROM_WIN32(status);
                }
            }
            else
            {
                if ((status = NCryptOpenKey(hProv, &hKey, TEXT(CONTAINER_NAME), 0, 0)) != ERROR_SUCCESS)
                {
                    LOG("NCryptOpenKey failed 0x%08x;", status);
                    return HRESULT_FROM_WIN32(status);
                }
            }

            // status = NCryptExportKey(hKey, 0, BCRYPT_RSAPRIVATE_BLOB, NULL, NULL, 0, &needed, 0);
            // if (status != ERROR_SUCCESS)
            //     return  HRESULT_FROM_WIN32(status);

            // buffer = (PBYTE)calloc(needed, sizeof(BYTE));
            // if (!buffer)
            //     return E_OUTOFMEMORY;

            // status = NCryptExportKey(hKey, 0, BCRYPT_RSAPRIVATE_BLOB, NULL, buffer, needed, &needed, 0);
            // if (status != ERROR_SUCCESS)
            // {
            //     free(buffer);
            //     return HRESULT_FROM_WIN32(status);
            // }

            // *keyOut = buffer;
            // *len = needed;

            *pKeyOut = hKey;
            return S_OK;
        }

        // long __thiscall CCertObject::CreatePKCS10Base64(CCertObject *this,ulong param_1,ulong param_2,bool param_3,CStringT<> *param_4) @ 0x1004964c
        HRESULT GenerateCertificateRequest(NCRYPT_PROV_HANDLE hProv, NCRYPT_KEY_HANDLE hKey, std::string &csrOut)
        {
            /**
             * Notes: N/A
             */

            // PCERT_PUBLIC_KEY_INFO pPublicKeyInfo = NULL;
            DWORD cbPublicKeyInfo = 0;
            if (!CryptExportPublicKeyInfo(hKey, 0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, NULL, &cbPublicKeyInfo))
            {
                LOG("CryptExportPublicKeyInfo failed to get size 0x%08x;", GetLastError());
                return HRESULT_FROM_WIN32(GetLastError());
            }

            std::vector<BYTE> publicKeyInfo(cbPublicKeyInfo);
            PCERT_PUBLIC_KEY_INFO pPublicKeyInfo = (PCERT_PUBLIC_KEY_INFO)publicKeyInfo.data();
            if (!CryptExportPublicKeyInfo(hKey, 0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pPublicKeyInfo, &cbPublicKeyInfo))
            {
                LOG("CryptExportPublicKeyInfo failed 0x%08x;", GetLastError());
                return HRESULT_FROM_WIN32(GetLastError());
            }

            FILETIME now;
            GetSystemTimeAsFileTime(&now);

            BYTE signingTimeEncoded[256];
            DWORD signingTimeEncodedSize = sizeof(signingTimeEncoded);
            if (!CryptEncodeObjectEx(X509_ASN_ENCODING, szOID_RSA_signingTime, &now, 0, nullptr, signingTimeEncoded, &signingTimeEncodedSize))
            {
                LOG("CryptEncodeObjectEx failed for signing time 0x%08x;", GetLastError());
                return HRESULT_FROM_WIN32(GetLastError());
            }

            CRYPT_ATTR_BLOB signingBlob = {};
            signingBlob.cbData = signingTimeEncodedSize;
            signingBlob.pbData = signingTimeEncoded;

            CRYPT_ATTRIBUTE signingAttr = {};
            signingAttr.pszObjId = szOID_RSA_signingTime;
            signingAttr.cValue = 1;
            signingAttr.rgValue = &signingBlob;

            CERT_RDN_ATTR cnAttr = {};
            cnAttr.pszObjId = szOID_COMMON_NAME;
            cnAttr.dwValueType = CERT_RDN_UNICODE_STRING;
            cnAttr.Value.pbData = (BYTE *)L"MSIDCRL";
            cnAttr.Value.cbData = sizeof(L"MSIDCRL");

            CERT_RDN rdn = {};
            rdn.cRDNAttr = 1;
            rdn.rgRDNAttr = &cnAttr;

            CERT_NAME_INFO nameInfo = {};
            nameInfo.cRDN = 1;
            nameInfo.rgRDN = &rdn;

            BYTE subjectEncoded[256];
            DWORD subjectEncodedSize = sizeof(subjectEncoded);
            if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_NAME, &nameInfo, 0, nullptr, subjectEncoded, &subjectEncodedSize))
            {
                LOG("CryptEncodeObjectEx failed for subject 0x%08x;", GetLastError());
                return HRESULT_FROM_WIN32(GetLastError());
            }

            CERT_REQUEST_INFO req = {};
            req.dwVersion = 0;
            req.Subject.cbData = subjectEncodedSize;
            req.Subject.pbData = subjectEncoded;
            req.SubjectPublicKeyInfo = *pPublicKeyInfo;
            req.cAttribute = 1;
            req.rgAttribute = &signingAttr;

            CRYPT_ALGORITHM_IDENTIFIER sigAlg = {};
            sigAlg.pszObjId = szOID_RSA_SHA1RSA;

            DWORD csrSize = 0;
            if (!CryptSignAndEncodeCertificate(hProv, 0, X509_ASN_ENCODING, X509_CERT_REQUEST_TO_BE_SIGNED, &req, &sigAlg, nullptr, nullptr, &csrSize))
            {
                LOG("CryptSignAndEncodeCertificate failed to get size 0x%08x;", GetLastError());
                return HRESULT_FROM_WIN32(GetLastError());
            }

            std::vector<BYTE> csr(csrSize);
            if (!CryptSignAndEncodeCertificate(hProv, 0, X509_ASN_ENCODING, X509_CERT_REQUEST_TO_BE_SIGNED, &req, &sigAlg, nullptr, csr.data(), &csrSize))
            {
                LOG("CryptSignAndEncodeCertificate failed 0x%08x;", GetLastError());
                return HRESULT_FROM_WIN32(GetLastError());
            }

            csrOut.assign(base64::to_base64({(char *)csr.data(), csr.size()}));

            return S_OK;
        }

        HRESULT StoreProvisioningCertificate(std::string cert)
        {
            const auto data = base64::from_base64(cert);

            HCERTSTORE hStore = NULL;
            PCCERT_CONTEXT pCert = NULL;
            HRESULT hr = E_FAIL;
            CRYPT_KEY_PROV_INFO kpi = {0};
            NCRYPT_PROV_HANDLE hProv = 0;
            NCRYPT_KEY_HANDLE hKey = 0;
            SECURITY_STATUS status;

            BYTE thumbprint[20];
            DWORD thumbprintSize = sizeof(thumbprint);
            char thumbprintHex[41];

            hStore = CertOpenStore((LPCSTR)CERT_STORE_PROV_SYSTEM, 0, 0,
                                   CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
            if (!hStore)
                return HRESULT_FROM_WIN32(GetLastError());

            pCert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, (LPBYTE)data.c_str(), data.length());
            if (!pCert)
            {
                hr = HRESULT_FROM_WIN32(GetLastError());
                LOG("CertCreateCertificateContext failed 0x%08x", hr);
                goto cleanup;
            }

            kpi.pwszContainerName = TEXT(CONTAINER_NAME);
            kpi.pwszProvName = MS_KEY_STORAGE_PROVIDER;
            kpi.dwProvType = 0;
            kpi.dwKeySpec = 0;

            if (!CertSetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, 0, &kpi))
            {
                hr = HRESULT_FROM_WIN32(GetLastError());
                LOG("CertSetCertificateContextProperty failed 0x%08x", hr);
                goto cleanup;
            }

            if (!CertAddCertificateContextToStore(hStore, pCert, CERT_STORE_ADD_REPLACE_EXISTING, NULL))
            {
                hr = HRESULT_FROM_WIN32(GetLastError());
                LOG("CertAddCertificateContextToStore failed 0x%08x", hr);
                goto cleanup;
            }

            if (!CertGetCertificateContextProperty(
                    pCert,
                    CERT_HASH_PROP_ID,
                    thumbprint,
                    &thumbprintSize))
            {
                hr = HRESULT_FROM_WIN32(GetLastError());
                LOG("CertGetCertificateContextProperty failed 0x%08x", hr);
                goto cleanup;
            }

            {
                config_store_t cs{storage::db_path()};
                cs.set("DeviceCertThumbprint", base64::to_base64({(char *)thumbprint, thumbprintSize}));
            }

            hr = S_OK;

        cleanup:
            if (pCert)
                CertFreeCertificateContext(pCert);
            if (hStore)
                CertCloseStore(hStore, 0);
            return hr;
        }

        HRESULT FetchCertificate(std::string csr, std::string &device_cert)
        {
            HRESULT hr = S_OK;
            std::string rst_endpoint = g_provisionDeviceEndpoint;
            json request = {{"csr", csr}};

            std::string body = request.dump();
            std::vector<std::string> additional_headers{};

            {
                token_t token;
                token_store_t token_store{storage::db_path()};
                if (!token_store.retrieve(device_id(), L"http://Passport.NET/tb", token))
                    return E_FAIL;

                additional_headers.push_back("Authorization: Bearer " + token.token);
            }

            net::client_t client{};
            net::result_t result = client.post(rst_endpoint, body, "application/json", additional_headers);
            if (result.ok())
            {
                return HRESULT_FROM_CURLE(result.curl_error);
            }

            if (result.status_code != 200 && result.status_code != 401)
            {
                LOG("GetDeviceId failed with status code %ld", result.status_code);
                return HRESULT_FROM_HTTP(result.status_code);
            }

            auto response = json::parse(result.body, nullptr, false);
            if (response.is_discarded())
            {
                LOG("GetDeviceId failed invalid JSON %s", result.body.c_str());
                return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
            }

            device_cert.assign(response["device_cert"].get<std::string>());

            return S_OK;
        }
    }

    namespace user
    {
        HRESULT RegisterDevice()
        {
            HRESULT hr = S_OK;
            BYTE rgDeviceId[20];
            DWORD cbDeviceId = 20;
            char deviceIdHex[41]{0};

            UCHAR member_name_bytes[16];
            char member_name[33];
            UCHAR password_bytes[16];
            char password[33];

            if (FAILED(hr = GetDeviceUniqueID((LPBYTE)PERSONALISATION_VALUE, strlen(PERSONALISATION_VALUE), 1, rgDeviceId, &cbDeviceId)))
            {
                LOG("GetDeviceUniqueID returned 0x%08x", hr);
                return hr;
            }

            NTSTATUS status = BCryptGenRandom(NULL, member_name_bytes, sizeof(member_name_bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            if (!BCRYPT_SUCCESS(status))
            {
                LOG("BCryptGenRandom failed: 0x%08X\n", status);
                return HRESULT_FROM_NT(status);
            }

            status = BCryptGenRandom(NULL, password_bytes, sizeof(password_bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            if (!BCRYPT_SUCCESS(status))
            {
                LOG("BCryptGenRandom failed: 0x%08X\n", status);
                return HRESULT_FROM_NT(status);
            }

            util::bytes_to_hex(rgDeviceId, cbDeviceId, deviceIdHex);
            util::bytes_to_hex(member_name_bytes, sizeof(member_name_bytes), member_name);
            util::bytes_to_hex(password_bytes, sizeof(password_bytes), password);

            std::string rst_endpoint = g_registerDeviceEndpoint;
            std::string_view device_id{deviceIdHex, cbDeviceId * 2};
            std::string_view member_name_str{member_name};
            std::string_view password_str{password};

            json request = {
                {"username", member_name_str},
                {"password", password_str},
                {"device_id", device_id}};

            net::client_t client{};
            net::result_t result = client.post(rst_endpoint, request.dump(), "application/json");
            if (result.curl_error != CURLE_OK)
            {
                return HRESULT_FROM_CURLE(result.curl_error);
            }

            if (result.status_code != 200 && result.status_code != 401)
            {
                LOG("GetDeviceId failed with status code %ld", result.status_code);
                return HRESULT_FROM_HTTP(result.status_code);
            }

            auto response = json::parse(result.body, nullptr, false);
            if (response.is_discarded())
            {
                LOG("GetDeviceId failed invalid JSON %s", result.body.c_str());
                return HRESULT_FROM_HTTP(result.status_code);
            }

            auto identity_json = response["identity"];
            {
                identity_t identity;
                identity_store_t identity_store{storage::db_path()};
                identity.identity = identity_json["username"].get<std::string>();
                identity.display_name = device_id;
                identity.puid = identity_json["puid"].get<uint64_t>();
                identity.cid = identity_json["cid"].get<std::string>();

                if (!identity_store.store(identity))
                {
                    LOG("Failed to store identity: %s (PUID: %llu, CUID: %s, Email: %s)",
                        identity.identity.c_str(),
                        identity.puid,
                        identity.cid.c_str(),
                        identity.email.c_str());

                    return E_FAIL;
                }

                LOG("Stored identity: %s (PUID: %llu, CUID: %s, Email: %s)",
                    identity.identity.c_str(),
                    identity.puid,
                    identity.cid.c_str(),
                    identity.email.c_str());
            }

            if (!response.contains("security_tokens") || !response["security_tokens"].is_array())
            {
                LOG("%s", "No security tokens found in response for DEVICE");
            }
            else
            {
                token_store_t token_store{storage::db_path()};

                const auto &tokens = response["security_tokens"];
                for (size_t i = 0; i < tokens.size(); i++)
                {
                    const auto &token = tokens[i];

                    token_t t;
                    t.identity = identity_json["username"].get<std::string>();
                    t.service = token["service_target"].get<std::string>();
                    t.token = token["token"].get<std::string>();
                    t.type = token["token_type"].get<std::string>();
                    t.created = token["created"].get<std::string>();
                    t.expires = token["expires"].get<std::string>();

                    if (!token_store.store(t))
                    {
                        LOG("Failed to store token for DEVICE: %s (Type: %s, Expires: %s)",
                            t.service.c_str(),
                            t.type.c_str(),
                            t.expires.c_str());

                        continue;
                    }

                    LOG("Stored token for DEVICE: %s (Type: %s, Expires: %s)",
                        t.service.c_str(),
                        t.type.c_str(),
                        t.expires.c_str());
                }
            }

            {
                config_store_t cs{db_path()};
                cs.set("DeviceDefaultID", identity_json["username"].get<std::string>());
            }

            return S_OK;
        }
    }

    HRESULT FetchDeviceCertificate()
    {
        HRESULT hr = S_OK;
        NCRYPT_PROV_HANDLE hProv = 0;
        NCRYPT_KEY_HANDLE hKey = 0;
        SECURITY_STATUS status = 0;
        std::string csr;
        std::string cert;

        if ((status = NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0)) != ERROR_SUCCESS)
        {
            LOG("NCryptOpenStorageProvider failed 0x%08x;", status);
            return HRESULT_FROM_WIN32(status);
        }

        if (FAILED(hr = cert::GenerateCertKey(hProv, &hKey)))
        {
            LOG("GenerateCertKey failed 0x%08x", hr);
            return hr;
        }

        if (FAILED(hr = cert::GenerateCertificateRequest(hProv, hKey, csr)))
        {
            LOG("GenerateCertificateRequest failed 0x%08x", hr);
            return hr;
        }

        if (FAILED(hr = cert::FetchCertificate(csr, cert)))
        {
            LOG("FetchCertificate failed 0x%08x", hr);
            return hr;
        }

        if (FAILED(hr = cert::StoreProvisioningCertificate(cert)))
        {
            LOG("StoreProvisioningCertificate returned 0x%08x", hr);
            return hr;
        }

        LOG("%s", "Stored provisioning certificate!");

        return S_OK;
    }

    HRESULT FindDeviceCert(BOOL bGenerateIfMissing, std::string &device_cert_thumb)
    {
        HRESULT hr = S_OK;
        PCCERT_CONTEXT pCert = NULL;
        HCERTSTORE hStore = NULL;

        {
            config_store_t cs{storage::db_path()};
            device_cert_thumb = cs.get("DeviceCertThumbprint");
        }

        if (!device_cert_thumb.empty())
        {
            std::string thumbprint = base64::from_base64(device_cert_thumb);
            hStore = CertOpenStore((LPCSTR)CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, L"MY");

            if (!hStore)
            {
                hr = HRESULT_FROM_WIN32(GetLastError());
                goto cleanup;
            }

            CRYPT_HASH_BLOB hashBlob;
            hashBlob.cbData = thumbprint.size();
            hashBlob.pbData = (PBYTE)thumbprint.c_str();

            pCert = CertFindCertificateInStore(hStore, X509_ASN_ENCODING, 0, CERT_FIND_HASH, &hashBlob, NULL);

            if (!pCert)
            {
                goto missing;
            }

            SYSTEMTIME sysNow;
            FILETIME ftNow;
            GetSystemTime(&sysNow);
            SystemTimeToFileTime(&sysNow, &ftNow);

            if (CompareFileTime(&ftNow, &pCert->pCertInfo->NotAfter) > 0)
            {
                goto missing;
            }

            return S_OK;
        }

    missing:
        if (bGenerateIfMissing)
        {
            if (FAILED(hr = FetchDeviceCertificate()))
            {
                goto cleanup;
            }

            hr = FindDeviceCert(FALSE, device_cert_thumb);
            goto cleanup;
        }

        hr = CRYPT_E_NOT_FOUND;

    cleanup:
        if (pCert != nullptr)
            CertFreeCertificateContext(pCert);
        if (hStore != nullptr)
            CertCloseStore(hStore, 0);

        return hr;
    }

    HRESULT EnsureProvisionedAsync()
    {
        HRESULT hr = S_OK;

        {
            config_store_t cs{storage::db_path(), true};
            auto default_id = cs.get("DeviceDefaultID");
            if (default_id.empty())
            {
                if (FAILED(hr = user::RegisterDevice()))
                {
                    LOG("RegisterDevice returned 0x%08x", hr);
                    return hr;
                }
            }
        }

        std::string thumb;
        if (FAILED(hr = FindDeviceCert(TRUE, thumb)))
        {
            LOG("FindDeviceCert returned 0x%08x", hr);
            return hr;
        }

        return S_OK;
    }
}