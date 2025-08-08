
#include <windows.h>
#include "config.h"
#include "util.h"
#include "log.h"

static LPCWSTR g_KeyNameProduction = TEXT("Software\\Microsoft\\IdentityCRL\\Environment\\Production");
static LPCWSTR g_KeyNameInternal = TEXT("Software\\Microsoft\\IdentityCRL\\Environment\\Internal");

namespace wlidsvc::config
{
    static config_result_t<std::wstring> get_wstring(HKEY hKeyRoot, LPCWSTR lpszPath, LPCWSTR lpszValue)
    {
        util::hkey_t hKey;
        DWORD disposition;
        LONG status = RegCreateKeyEx(hKeyRoot, lpszPath, 0, NULL, 0, 0x2001, NULL, hKey.put(), &disposition);
        if (status != ERROR_SUCCESS)
            return error<std::wstring>(HRESULT_FROM_WIN32(status));

        DWORD dwLen;
        status = RegQueryValueEx(hKey.get(), lpszValue, NULL, &disposition, NULL, &dwLen);
        if (status != ERROR_SUCCESS)
            return error<std::wstring>(HRESULT_FROM_WIN32(status));

        void *data = new (std::nothrow) char[dwLen + 1];
        if (data == nullptr)
            return error<std::wstring>(E_OUTOFMEMORY);

        status = RegQueryValueEx(hKey.get(), lpszValue, NULL, &disposition, (LPBYTE)data, &dwLen);
        if (status != ERROR_SUCCESS)
            return error<std::wstring>(HRESULT_FROM_WIN32(status));

        return result(std::wstring((const wchar_t *)data, dwLen));
    }

    static config_result_t<std::string> get_string(HKEY hKeyRoot, LPCWSTR lpszPath, LPCWSTR lpszValue)
    {
        auto wstr = get_wstring(hKeyRoot, lpszPath, lpszValue);
        if (!wstr.ok())
            return error<std::string>(wstr.hr());

        std::wstring res = wstr.value();
        const char *str = wchar_to_char(res.c_str());
        if (str == nullptr)
            return error<std::string>(E_OUTOFMEMORY);

        std::string str_{str};
        delete[] str;

        return result(str_);
    }

    const config_result_t<environment_t> environment()
    {
        WCHAR buf[MAX_PATH] = {};
        util::hkey_t hKey;
        DWORD disposition;
        LONG status = RegCreateKeyEx(HKEY_CURRENT_USER, TEXT("Software\\Microsoft\\IdentityCRL"), 0, NULL, 0, 0x2001, NULL, hKey.put(), &disposition);
        if (status != ERROR_SUCCESS)
            return error<environment_t>(HRESULT_FROM_WIN32(status));

        DWORD dwLen = MAX_PATH * sizeof(WCHAR);
        status = RegQueryValueEx(hKey.get(), TEXT("ServiceEnvironment"), NULL, &disposition, (PBYTE)buf, &dwLen);
        if (status != ERROR_SUCCESS)
        {
            if (status == ERROR_FILE_NOT_FOUND)
            {
                return result(environment_t::production);
            }

            return error<environment_t>(HRESULT_FROM_WIN32(status));
        }

        if (_wcsicmp(buf, TEXT("production")) != 0)
        {
            return result(environment_t::internal);
        }
        return result(environment_t::production);
    }

    static const std::string log_endpoint_default = "ws://172.16.0.2:5678/";
    const config_result_t<std::string> log_endpoint()
    {
        auto env_res = environment();
        if (!env_res.ok())
            return error<std::string>(env_res.hr());

        auto res = get_string(
            HKEY_CURRENT_USER,
            env_res.value() == environment_t::production ? g_KeyNameProduction : g_KeyNameInternal,
            TEXT("LogEndpoint"));

        if (!res.ok())
        {
            if (res.hr() == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
                return result(log_endpoint_default);
        }

        return res;
    }
}