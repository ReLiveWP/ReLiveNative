#include "deviceid.h"
#include "log.h"
#include "util.h"
#include "config.h"
#include "storage.h"
#include "urls.h"
#include "microrest.h"

#include <string.h>
#include <malloc.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/rsa.h>
#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_csr.h>

#include <ncrypt.h>
#include <wincrypt.h>
#include <string>
#include <base64.hpp>
#include <wlidcomm.h>

#include <cerrno>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

#ifndef CERT_SYSTEM_STORE_CURRENT_USER
#define CERT_SYSTEM_STORE_LOCATION_SHIFT 16
#define CERT_SYSTEM_STORE_CURRENT_USER_ID 1
#define CERT_SYSTEM_STORE_CURRENT_USER (CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT)
#endif

#ifndef CERT_NCRYPT_KEY_HANDLE_PROP_ID
#define CERT_NCRYPT_KEY_HANDLE_PROP_ID 78
#endif

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
    int generate_private_key(unsigned char **key, size_t *len);
    int generate_csr(unsigned char *key, size_t key_len, unsigned char **csr_out, size_t *len_out);
    void bytes_to_hex(const unsigned char *bytes, size_t len, char *out);
    int mbedtls_import_from_cng(PBYTE blob, DWORD blobLen, mbedtls_pk_context *pk);

    HRESULT GenerateProvisioningCertificateRequest(LPSTR *pszCertRequest, DWORD *pcbCertRequest)
    {
        unsigned char *key = nullptr;
        unsigned char *csr = nullptr;
        size_t len = 0;
        size_t csr_len = 0;
        int ret = generate_private_key(&key, &len);
        if (ret != 0)
            return HRESULT_FROM_WIN32(ret);

        ret = generate_csr(key, len, &csr, &csr_len);
        if (ret != 0)
            return HRESULT_FROM_WIN32(ret);

        std::string csr_s = base64::to_base64({(char *)csr, csr_len});

        auto szCertRequest = (LPSTR)calloc(csr_s.length() + 1, sizeof(CHAR));
        strcpy(szCertRequest, csr_s.c_str());

        *pszCertRequest = szCertRequest;
        *pcbCertRequest = csr_s.length();

        return S_OK;
    }

    HRESULT StoreProvisioningCertificate(LPCSTR szCertificate)
    {
        const auto data = base64::from_base64({szCertificate});

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

    HRESULT FetchDeviceCertificate()
    {
        HRESULT hr;
        LPSTR szCertRequest = NULL;
        DWORD cbCertRequest = 0;
        if (FAILED(hr = wlidsvc::deviceid::GenerateProvisioningCertificateRequest(&szCertRequest, &cbCertRequest)))
        {
            LOG("GenerateProvisioningCertificateRequest returned 0x%08x", hr);
            return hr;
        }

        BYTE rgDeviceId[20];
        DWORD cbDeviceId = 20;
        char deviceIdHex[41]{0};

        if (FAILED(hr = GetDeviceUniqueID((LPBYTE)PERSONALISATION_VALUE, strlen(PERSONALISATION_VALUE), 1, rgDeviceId, &cbDeviceId)))
        {
            LOG("GetDeviceUniqueID returned 0x%08x", hr);
            return hr;
        }

        util::bytes_to_hex(rgDeviceId, cbDeviceId, deviceIdHex);

        std::string rst_endpoint = g_provisionDeviceEndpoint;
        std::string_view device_id{deviceIdHex, cbDeviceId * 2};
        std::string_view cert_request{szCertRequest, cbCertRequest};
        json request = {
            {"device_id", device_id},
            {"csr", cert_request}};

        std::string body = request.dump();
        std::vector<std::string> additional_headers{};

        {
            token_t token;
            token_store_t token_store{storage::db_path()};
            if (!token_store.retrieve(default_id(), L"http://Passport.NET/tb", token))
                return E_FAIL;

            additional_headers.push_back("Authorization: Bearer " + token.token);
        }

        net::client_t client{};
        net::result_t result = client.post(rst_endpoint, body, "application/json", additional_headers);
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

        // {  "identity": { puid: 12345, cuid: "asdf" }, security_tokens:[{..}], "device_cert": "MII..." } identity_store_t identity_store{storage::db_path()};

        {
            identity_t identity;
            identity_store_t identity_store{storage::db_path()};
            identity.identity = identity_json["username"].get<std::string>();
            identity.display_name = device_id;
            identity.puid = identity_json["puid"].get<uint64_t>();
            identity.cuid = identity_json["cid"].get<std::string>();

            if (!identity_store.store(identity))
            {
                LOG("Failed to store identity: %s (PUID: %llu, CUID: %s, Email: %s)",
                    identity.identity.c_str(),
                    identity.puid,
                    identity.cuid.c_str(),
                    identity.email.c_str());

                return E_FAIL;
            }

            LOG("Stored identity: %s (PUID: %llu, CUID: %s, Email: %s)",
                identity.identity.c_str(),
                identity.puid,
                identity.cuid.c_str(),
                identity.email.c_str());
        }

        {
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
        }

        auto device_cert = response["device_cert"].get<std::string>();
        if (FAILED(hr = wlidsvc::deviceid::StoreProvisioningCertificate(device_cert.c_str())))
        {
            LOG("StoreProvisioningCertificate returned 0x%08x", hr);
            return hr;
        }

        LOG("%s", "Stored provisioning certificate!");

        return S_OK;
    }

    int generate_csr(unsigned char *key, size_t key_len, unsigned char **csr_out, size_t *len_out)
    {
        mbedtls_x509write_csr req{};
        mbedtls_entropy_context entropy{};
        mbedtls_ctr_drbg_context ctr_drbg{};
        mbedtls_pk_context pk{};
        int ret = 0;
        HRESULT hr = S_OK;
        BYTE rgDeviceId[20];
        DWORD cbDeviceId = 20;
        char deviceIdHex[41]{0};
        std::string common_name{};
        unsigned char *data = nullptr;
        unsigned char *tmp = nullptr;

        mbedtls_x509write_csr_init(&req);
        mbedtls_pk_init(&pk);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_entropy_init(&entropy);

        if (FAILED(hr = GetDeviceUniqueID((LPBYTE)PERSONALISATION_VALUE, strlen(PERSONALISATION_VALUE), 1, rgDeviceId, &cbDeviceId)))
        {
            LOG(" failed\n  !  GetDeviceUniqueID returned 0x%08x", hr);
            return hr;
        }

        util::bytes_to_hex(rgDeviceId, cbDeviceId, deviceIdHex);

        common_name = "CN=" + std::string(deviceIdHex);

        // TODO: might be worth using GetDeviceUniqueID for personalisation value
        if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                         (const unsigned char *)PERSONALISATION_VALUE,
                                         strlen(PERSONALISATION_VALUE))) != 0)
        {
            LOG(" failed\n  !  mbedtls_ctr_drbg_seed returned %d", ret);
            goto done;
        }

        mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA1);

        if ((ret = mbedtls_x509write_csr_set_key_usage(&req, MBEDTLS_X509_KU_DIGITAL_SIGNATURE)) != 0)
        {
            LOG(" failed\n  !  mbedtls_x509write_csr_set_key_usage returned %d", ret);
            goto done;
        }

        if ((ret = mbedtls_x509write_csr_set_ns_cert_type(&req,
                                                          MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT |
                                                              MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER)) != 0)
        {
            LOG(" failed\n  !  mbedtls_x509write_csr_set_ns_cert_type returned %d", ret);
            goto done;
        }

        if ((ret = mbedtls_x509write_csr_set_subject_name(&req, common_name.c_str())) != 0)
        {
            LOG(" failed\n  !  mbedtls_x509write_csr_set_subject_name returned %d", ret);
            goto done;
        }

        LOG("requesting certificate with %s", common_name.c_str());

        if ((ret = mbedtls_import_from_cng(key, key_len, &pk)) != ERROR_SUCCESS)
        {
            LOG(" failed\n  !  mbedtls_import_from_cng returned %d", ret);
            goto done;
        }

        mbedtls_x509write_csr_set_key(&req, &pk);

        tmp = (unsigned char *)calloc(16384, sizeof(unsigned char));
        if ((ret = mbedtls_x509write_csr_der(&req, tmp, 16384, mbedtls_ctr_drbg_random, &ctr_drbg)) < 0)
        {
            LOG(" failed\n  !  mbedtls_x509write_csr_der returned %d", ret);
            goto done;
        }

        data = (unsigned char *)calloc(ret, sizeof(unsigned char));
        memcpy(data, tmp + 16384 - ret, ret);

        LOG("%s", "working...");

        *csr_out = data;
        *len_out = ret;

        ret = 0;

        goto cleanup;

    done:
        if (data != nullptr)
            free(data);

    cleanup:
        if (tmp != nullptr)
            free(tmp);

        mbedtls_x509write_csr_free(&req);
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return ret;
    }

    int generate_private_key(unsigned char **keyOut, size_t *len)
    {
        NCRYPT_PROV_HANDLE hProv = 0;
        NCRYPT_KEY_HANDLE hKey = 0;
        SECURITY_STATUS status = 0;
        HRESULT hr = S_OK;
        DWORD keyLengthBits = 2048;
        DWORD needed;
        PBYTE buffer;

        if ((status = NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0)) != ERROR_SUCCESS)
        {
            LOG("NCryptOpenStorageProvider failed 0x%08x;", status);
            return -1;
        }

        status = NCryptCreatePersistedKey(hProv, &hKey, BCRYPT_RSA_ALGORITHM, TEXT(CONTAINER_NAME), 0, 0);
       
        // TODO: don't ship this <3
        if (status == NTE_EXISTS)
        {
            if ((status = NCryptOpenKey(hProv, &hKey, TEXT(CONTAINER_NAME), 0, 0)) != ERROR_SUCCESS)
            {
                LOG("NCryptOpenKey failed 0x%08x;", status);
                return -1;
            }
            NCryptDeleteKey(hKey, 0);

            status = NCryptCreatePersistedKey(hProv, &hKey, BCRYPT_RSA_ALGORITHM, TEXT(CONTAINER_NAME), 0, 0);
        }

        if (status != NTE_EXISTS)
        {
            if (status != ERROR_SUCCESS)
            {
                LOG("NCryptCreatePersistedKey failed 0x%08x;", status);
                return -1;
            }

            if ((status = NCryptSetProperty(hKey, NCRYPT_LENGTH_PROPERTY,
                                            (PBYTE)&keyLengthBits, sizeof(keyLengthBits), 0)) != ERROR_SUCCESS)
            {
                LOG("NCryptSetProperty NCRYPT_LENGTH_PROPERTY failed 0x%08x;", status);
                return -1;
            }

            DWORD exportPolicy = NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
            if ((status = NCryptSetProperty(hKey, NCRYPT_EXPORT_POLICY_PROPERTY,
                                            (PBYTE)&exportPolicy, sizeof(exportPolicy), 0)) != ERROR_SUCCESS)
            {
                LOG("NCryptSetProperty NCRYPT_EXPORT_POLICY_PROPERTY failed 0x%08x;", status);
                return -1;
            }

            DWORD keyUsage = NCRYPT_ALLOW_DECRYPT_FLAG | NCRYPT_ALLOW_SIGNING_FLAG;
            if ((status = NCryptSetProperty(hKey, NCRYPT_KEY_USAGE_PROPERTY,
                                            (PBYTE)&keyUsage, sizeof(keyUsage), 0)) != ERROR_SUCCESS)
            {
                LOG("NCryptSetProperty NCRYPT_KEY_USAGE_PROPERTY failed 0x%08x;", status);
                return -1;
            }

            if ((status = NCryptFinalizeKey(hKey, 0)) != ERROR_SUCCESS)
            {
                LOG("NCryptFinalizeKey failed 0x%08x;", status);
                return -1;
            }
        }
        else
        {
            if ((status = NCryptOpenKey(hProv, &hKey, TEXT(CONTAINER_NAME), 0, 0)) != ERROR_SUCCESS)
            {
                LOG("NCryptOpenKey failed 0x%08x;", status);
                return -1;
            }
        }

        status = NCryptExportKey(hKey, 0, BCRYPT_RSAPRIVATE_BLOB, NULL, NULL, 0, &needed, 0);
        if (status != ERROR_SUCCESS)
            return HRESULT_FROM_WIN32(status);

        buffer = (PBYTE)calloc(needed, sizeof(BYTE));
        if (!buffer)
            return E_OUTOFMEMORY;

        status = NCryptExportKey(hKey, 0, BCRYPT_RSAPRIVATE_BLOB, NULL, buffer, needed, &needed, 0);
        if (status != ERROR_SUCCESS)
        {
            free(buffer);
            return HRESULT_FROM_WIN32(status);
        }

        *keyOut = buffer;
        *len = needed;

        return S_OK;
    }

    int mbedtls_import_from_cng(PBYTE blob, DWORD blobLen, mbedtls_pk_context *pk)
    {
        int rc = 0;
        mbedtls_rsa_context *rsa = NULL;
        if (blobLen < sizeof(BCRYPT_RSAKEY_BLOB))
            return FALSE;

        BCRYPT_RSAKEY_BLOB *hdr = (BCRYPT_RSAKEY_BLOB *)blob;
        if (hdr->Magic != BCRYPT_RSAPRIVATE_MAGIC)
            return FALSE; // sanity

        PBYTE pPubExp, pModulus, pP, pQ;
        DWORD cbPubExp, cbModulus, cbP, cbQ;
        DWORD offset = sizeof(BCRYPT_RSAKEY_BLOB);
        cbPubExp = hdr->cbPublicExp;
        cbModulus = hdr->cbModulus;
        cbP = hdr->cbPrime1;
        cbQ = hdr->cbPrime2;

        pPubExp = blob + offset;
        offset += cbPubExp;
        pModulus = blob + offset;
        offset += cbModulus;
        pP = blob + offset;
        offset += cbP;
        pQ = blob + offset;
        offset += cbQ;

        mbedtls_pk_init(pk);
        if ((rc = mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) != 0)
            return rc;

        rsa = mbedtls_pk_rsa(*pk);
        mbedtls_rsa_init(rsa);

        if ((rc = mbedtls_rsa_import_raw(rsa, pModulus, cbModulus, pP, cbP, pQ, cbQ, NULL, 0, pPubExp, cbPubExp)) != 0)
            goto cleanup;

        if ((rc = mbedtls_rsa_complete(rsa)) != 0)
            goto cleanup;

        rc = mbedtls_rsa_check_privkey(rsa);

    cleanup:
        if (rc != 0)
            mbedtls_pk_free(pk);
        return rc;
    }
}