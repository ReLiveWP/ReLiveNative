#include <windows.h>
#include <curl/curl.h>

static void on_curl_error(CURLcode error_code)
{
    const char *error_msg = curl_easy_strerror(error_code);
    size_t len = MultiByteToWideChar(CP_UTF8, 0, error_msg, -1, NULL, 0);
    wchar_t *wide_error_msg = (wchar_t *)malloc((len + 1) * sizeof(wchar_t));
    if (wide_error_msg)
    {
        MultiByteToWideChar(CP_UTF8, 0, error_msg, -1, wide_error_msg, len);
        MessageBox(NULL, wide_error_msg, L"CURL Error", MB_OK | MB_ICONERROR);
        free(wide_error_msg);
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nShowCmd)
{
    // Initialize libcurl
    CURL *curl = curl_easy_init();
    if (!curl)
    {
        on_curl_error(CURLE_FAILED_INIT);
        return 1;
    }

    // Set up a simple GET request
    curl_easy_setopt(curl, CURLOPT_URL, "http://example.com");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "ReLiveNative/1.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L); // Set a timeout for the request

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK)
    {
        on_curl_error(res);
        goto exit;
    }

    MessageBox(NULL, L"Request completed successfully!", L"Success", MB_OK | MB_ICONINFORMATION);

exit:
    // Clean up
    curl_easy_cleanup(curl);
    return 0;
}