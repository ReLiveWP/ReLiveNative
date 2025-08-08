#include <windows.h>
#include <curl/curl.h>

static void show_dialog(const char *text)
{
    size_t len = MultiByteToWideChar(CP_UTF8, 0, text, -1, NULL, 0);
    wchar_t *wide_error_msg = (wchar_t *)malloc((len + 1) * sizeof(wchar_t));
    if (wide_error_msg)
    {
        MultiByteToWideChar(CP_UTF8, 0, text, -1, wide_error_msg, len);
        MessageBox(NULL, wide_error_msg, L"CURL Error", MB_OK);
        free(wide_error_msg);
    }
}

static void on_curl_error(CURLcode error_code)
{
    show_dialog(curl_easy_strerror(error_code));
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nShowCmd)
{
    CURLcode res;
    CURL *curl;

    res = curl_global_init(CURL_GLOBAL_ALL);
    if (res != CURLE_OK)
    {
        on_curl_error(res);
        goto exit;
    }

    curl = curl_easy_init();
    if (!curl)
    {
        on_curl_error(CURLE_FAILED_INIT);
        return 1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "https://wamwoowam.co.uk");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "ReLiveNative/1.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK)
    {
        on_curl_error(res);
        goto exit;
    }

    MessageBox(NULL, L"Request completed successfully!", L"Success", MB_OK);

exit:
    curl_easy_cleanup(curl);
    return 0;
}