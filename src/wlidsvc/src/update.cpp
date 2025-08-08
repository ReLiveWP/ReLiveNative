#include "update.h"
#include "log.h"
#include "microrest.h"

#include <cerrno>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

using namespace wlidsvc::net;

DWORD CheckForUpdatesThreadProc(LPVOID lpParam)
{
    Sleep(10000);

    client_t rest{};
    result_t resp = rest.get("https://wamwoowam.co.uk/ball/api/servers");
    if (resp.curl_error != CURLE_OK)
    {
        LOG("Failed to do curl: %s", resp.error_message().c_str());
    }
    else
    {
        auto data = json::parse(resp.body, nullptr, false);
        if (data.is_discarded())
        {
            LOG("Failed to parse JSON: \"%s\" is invalid.", resp.body.c_str());
        }
        else
        {
            LOG("ID: %s", data[0]["id"].dump().c_str());
        }
    }

    return 0;
}