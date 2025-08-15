
#include <windows.h>
#include "config.h"
#include "storage.h"
#include "util.h"
#include "log.h"
#include "microrest.h"
#include "urls.h"

#include <string>
#include <shlobj.h>
#include <sqlite3.h>

#include <cerrno>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

using namespace wlidsvc::util;
using namespace wlidsvc::storage;
using namespace wlidsvc::globals;

namespace wlidsvc::config
{
    static size_t OnWriteFile(void *contents, size_t size, size_t nmemb, HANDLE hFile);
    static HRESULT DownloadClientConfig();
    static HRESULT GetClientConfigVersion(std::string utf8path, int *lpVersion);
    static HRESULT DoClientConfigInitialization(BOOL isNested);

    constexpr LPCWSTR g_clientConfigDBFolder = TEXT("\\Volatile\\ReLiveWP");
#ifdef IS_PRODUCTION_BUILD
    constexpr LPCWSTR g_clientConfigDBName = TEXT("\\wlidconf.db");
#else
    constexpr LPCWSTR g_clientConfigDBName = TEXT("\\wlidconf-int.db");
#endif

    const std::wstring client_config_db_path()
    {
        WCHAR szAppData[MAX_PATH] = {0};
        SHGetSpecialFolderPath(NULL, szAppData, CSIDL_APPDATA, TRUE);

        const std::wstring folderPath = std::wstring(szAppData) + g_clientConfigDBFolder;
        if (GetFileAttributes(folderPath.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            CreateDirectory(folderPath.c_str(), NULL);
        }

        return folderPath + g_clientConfigDBName;
    }

    const HRESULT init_client_config(void)
    {
        EnterCriticalSection(&g_ClientConfigCritSect);
        if (g_ClientConfigReady)
        {
            LeaveCriticalSection(&g_ClientConfigCritSect);
            return S_OK;
        }

        if (g_ClientConfigDownloading)
        {
            LeaveCriticalSection(&g_ClientConfigCritSect);

            LOG("%s", "Client config is already being downloaded, waiting...");
            WaitForSingleObject(g_ClientConfigDownloadedEvent, INFINITE);

            return init_client_config();
        }
        else
        {
            g_ClientConfigDownloadedEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
            g_ClientConfigDownloading = TRUE;
            LeaveCriticalSection(&g_ClientConfigCritSect);
        }

        HRESULT hr = DoClientConfigInitialization(FALSE);
        if (FAILED(hr))
        {
            LOG("Failed to initialize client config: 0x%08x", hr);
        }

        EnterCriticalSection(&g_ClientConfigCritSect);
        g_ClientConfigReady = SUCCEEDED(hr);
        g_ClientConfigDownloading = false;
        SetEvent(g_ClientConfigDownloadedEvent);
        LeaveCriticalSection(&g_ClientConfigCritSect);

        return hr;
    }

    const environment_t environment()
    {
        return environment_t::production;
        
#ifdef IS_PRODUCTION_BUILD
        return environment_t::production;
#else
        return environment_t::internal;
#endif
    }

    static const std::string log_endpoint_default = "ws://172.16.0.2:5678/";
    const std::string log_endpoint()
    {
        config_store_t cs{db_path()};
        return cs.get("LogEndpoint", log_endpoint_default);
    }

    const std::wstring default_id()
    {
        config_store_t cs{db_path()};
        return utf8_to_wstring(cs.get("DefaultID"));
    }

    static size_t OnWriteFile(void *contents, size_t size, size_t nmemb, HANDLE hFile)
    {
        DWORD written;
        if (!WriteFile(hFile, contents, size * nmemb, &written, NULL))
        {
            LOG("Failed to write to file: 0x%08x", HRESULT_FROM_WIN32(GetLastError()));
            return 0; // return 0 to indicate failure
        }
        return size * nmemb; // return number of bytes written
    }

    static HRESULT DownloadClientConfig()
    {
        CURL *curl = curl_easy_init();
        if (!curl)
        {
            LOG("%s", "Failed to initialize curl for downloading client config.");
            return E_FAIL;
        }

        // microrest is designed for non-streaming text responses, so we can't use it here for downloading a file
        std::string utf8path = wlidsvc::util::wstring_to_utf8(client_config_db_path());
        std::string url = g_clientConfigEndpoint;
        LOG("Downloading client config from %s to %s", url.c_str(), utf8path.c_str());

        HANDLE hFile = CreateFile(client_config_db_path().c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            LOG("Failed to open file for writing: 0x%08x", HRESULT_FROM_WIN32(GetLastError()));
            curl_easy_cleanup(curl);
            return HRESULT_FROM_WIN32(GetLastError());
        }

        SetEndOfFile(hFile); // ensure the file is empty before writing

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
        curl_easy_setopt(curl, CURLOPT_USERAGENT, net::g_userAgent);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, OnWriteFile);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)hFile);
        curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            LOG("Failed to download client config: %s", curl_easy_strerror(res));
            CloseHandle(hFile);
            curl_easy_cleanup(curl);
            return HRESULT_FROM_WIN32(ERROR_NETWORK_UNREACHABLE);
        }

        CloseHandle(hFile);
        curl_easy_cleanup(curl);
        LOG("Client config downloaded successfully to %s", utf8path.c_str());
        return S_OK;
    }

    static HRESULT GetClientConfigVersion(std::string utf8path, int *lpVersion)
    {
        *lpVersion = 0;

        sqlite3 *db = nullptr;
        int code = SQLITE_OK;
        if ((code = sqlite3_open(utf8path.c_str(), &db)) != SQLITE_OK)
        {
            LOG("Failed to open client config DB at %s: %d", utf8path.c_str(), code);
            // we've already made sure the file exists, so this should only happen if the file is corrupted
            return HRESULT_FROM_WIN32(ERROR_FILE_CORRUPT);
        }

        {
            config_store_t cs{db};
            std::string version_str = cs.get("Version", {});
            if (version_str.empty())
            {
                LOG("%s", "Client config DB is invalid, redownloading...");
                sqlite3_close(db);
                return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
            }

            long version = strtol(version_str.c_str(), nullptr, 10);
            if (version <= 0)
            {
                LOG("Invalid client config version: %s", version_str.c_str());
                sqlite3_close(db);
                return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
            }

            *lpVersion = (int)version;
            LOG("Client config DB version: %d", version);

            sqlite3_close(db);

            return S_OK;
        }
    }

    static HRESULT DoClientConfigInitialization(BOOL isNested)
    {
        HRESULT hr = S_OK;
        int version;
        net::client_t client{};

        std::string utf8path = wlidsvc::util::wstring_to_utf8(client_config_db_path());
        DWORD dwAttrib = GetFileAttributes(client_config_db_path().c_str());
        if (dwAttrib == INVALID_FILE_ATTRIBUTES) // download required
            goto download;

        if (FAILED(hr = GetClientConfigVersion(utf8path, &version)))
        {
            LOG("Failed to get client config version: 0x%08x", hr);
            goto download;
        }

        {
            net::result_t result = client.get(g_clientConfigVersionEndpoint);
            if (result.curl_error != CURLE_OK)
            {
                LOG("Failed to do curl: %s", result.error_message().c_str());
                return HRESULT_FROM_WIN32(ERROR_NETWORK_UNREACHABLE);
            }

            auto data = json::parse(result.body, nullptr, false);
            if (data.is_discarded() || !data["min_version"].is_number_integer())
            {
                LOG("Failed to parse JSON: \"%s\" is invalid.", result.body.c_str());
                return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
            }

            auto min_version = data["min_version"].get<int>();
            if (min_version > version)
            {
                LOG("Client config version %d is lower than the minimum required version %d, redownloading...",
                    version, min_version);

                // delete the file and download it again
                DeleteFile(client_config_db_path().c_str());
                goto download;
            }

            LOG("Client config DB is valid, version: %d", version);
            hr = S_OK;

            goto end;
        }

    download:
        if (isNested)
            return E_UNEXPECTED; // prevent infinite loops if the download fails

        hr = DownloadClientConfig();
        if (FAILED(hr))
        {
            LOG("Failed to download client config: 0x%08x", hr);
            return hr;
        }

        return DoClientConfigInitialization(TRUE);
    end:
        return hr;
    }
}