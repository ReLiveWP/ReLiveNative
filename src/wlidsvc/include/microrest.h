#pragma once
#include <string>
#include <vector>
#include <curl/curl.h>

namespace wlidsvc::urest
{
    struct result_t
    {
        CURLcode curl_error = CURLE_OK;

        long status_code = 0;
        std::string body;
        std::string content_type;
        std::vector<std::string> headers;

        const std::string error_message() const
        {
            return {curl_easy_strerror(curl_error)};
        }
    };

    class client_t
    {
    public:
        client_t(CURL *curl = nullptr, std::vector<std::string> additionalHeaders = {})
            : additional_headers(additionalHeaders)
        {
            this->curl = (curl != nullptr ? curl : curl_easy_init());
        }

        ~client_t()
        {
            if (curl)
                curl_easy_cleanup(curl);
            curl_global_cleanup();
        }

        result_t get(const std::string &url, const std::vector<std::string> &customHeaders = {})
        {
            return request("GET", url, "", "", customHeaders);
        }

        result_t post(const std::string &url, const std::string &body,
                      const std::string &contentType = "application/json",
                      const std::vector<std::string> &customHeaders = {})
        {
            return request("POST", url, body, contentType, customHeaders);
        }

        result_t put(const std::string &url, const std::string &body,
                     const std::string &contentType = "application/json",
                     const std::vector<std::string> &customHeaders = {})
        {
            return request("PUT", url, body, contentType, customHeaders);
        }

        result_t del(const std::string &url, const std::vector<std::string> &customHeaders = {})
        {
            return request("DELETE", url, "", "", customHeaders);
        }

    private:
        CURL *curl = nullptr;
        std::string user_agent = "Mozilla/4.0 (compatible; MSIE 5.01; Windows CE) WLIDSVC/1.0, ReLiveWP/1.0 (+https://github.com/ReLiveWP/ReLiveWP)";
        std::vector<std::string> additional_headers = {};

        static size_t OnWrite(void *contents, size_t size, size_t nmemb, result_t *result)
        {
            result->body.append((char *)contents, size * nmemb);
            return size * nmemb;
        }

        static size_t OnHeader(char *buffer, size_t size, size_t nitems, result_t *result)
        {
            result->headers.emplace_back(buffer, size * nitems);
            return size * nitems;
        }

        result_t request(const std::string &method, const std::string &url,
                         const std::string &body = "",
                         const std::string &contentType = "",
                         const std::vector<std::string> &customHeaders = {}) const
        {
            result_t resp{};

            if (!curl)
            {
                resp.curl_error = CURLE_FAILED_INIT;
                return resp;
            }

            curl_easy_reset(curl); // Reset previous options
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, OnWrite);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
            curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, OnHeader);
            curl_easy_setopt(curl, CURLOPT_HEADERDATA, &resp);
            curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent.c_str());

            struct curl_slist *headersList = nullptr;
            if (!contentType.empty())
                headersList = curl_slist_append(headersList, ("Content-Type: " + contentType).c_str());

            for (const auto &h : customHeaders)
                headersList = curl_slist_append(headersList, h.c_str());
            for (const auto &h : additional_headers)
                headersList = curl_slist_append(headersList, h.c_str());


            if (headersList)
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headersList);

            if (method == "POST")
            {
                curl_easy_setopt(curl, CURLOPT_POST, 1L);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
            }
            else if (method == "PUT")
            {
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
            }
            else if (method == "DELETE")
            {
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
            }

            resp.curl_error = curl_easy_perform(curl);

            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp.status_code);

            char *ct = nullptr;
            if (curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ct) == CURLE_OK && ct)
                resp.content_type = ct;

            if (headersList)
                curl_slist_free_all(headersList);

            return resp;
        }
    };
}
