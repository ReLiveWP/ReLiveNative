#include "update.h"
#include "log.h"
#include "microrest.h"
#include "storage.h"

#include <string>
#include <sstream>
#include <chrono>

#include <cerrno>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

// #define ONLY_C_LOCALE 1
// #include <date/date.h>

using namespace wlidsvc;
using namespace wlidsvc::net;
using namespace wlidsvc::storage;

DWORD CheckForUpdatesThreadProc(LPVOID lpParam)
{
    Sleep(5000);

    auto now = std::chrono::system_clock::now();
    token_store_t token_store{db_path()};

    std::vector<token_t> tokens;
    std::copy(token_store.begin(), token_store.end(), std::back_inserter(tokens));

    for (const auto &token : tokens)
    {
        LOG("Token in store - Identity: %s, Service: %s, Type: %s, Expires: %s",
            token.identity.c_str(),
            token.service.c_str(),
            token.type.c_str(),
            token.expires.c_str());

        if (token.service == "http://Passport.NET/tb")
            continue;

        // std::istringstream ss{token.expires};
        // date::sys_time<std::chrono::nanoseconds> tp;
        // std::chrono::minutes offset;
        // ss >> date::parse("%Y-%m-%dT%H:%M:%S%Ez", tp);

        // if (ss.fail())
        // {
        //     // invalid time format, log and delete
        //     LOG("Failed to parse expiration time for token (Identity: %s, Service: %s). Deleting token. Expiration string: %s",
        //         token.identity.c_str(),
        //         token.service.c_str(),
        //         token.expires.c_str());
        //     token_store.remove(token);
        //     continue;
        // }

        // if (tp < now)
        // {
        //     LOG("Token expired for Identity: %s, Service: %s. Deleting token. Expiration time was: %s",
        //         token.identity.c_str(),
        //         token.service.c_str(),
        //         token.expires.c_str());
        //     token_store.remove(token);
        // }
        // else
        // {
        //     LOG("Token is still valid for Identity: %s, Service: %s. Expiration time is: %s",
        //         token.identity.c_str(),
        //         token.service.c_str(),
        //         token.expires.c_str());
        // }
    }

    return 0;
}