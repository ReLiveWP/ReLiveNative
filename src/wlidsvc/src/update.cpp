#include "update.h"
#include "log.h"
#include "microrest.h"
#include "storage.h"
#include "config.h"

#include <string>
#include <sstream>
#include <chrono>
#include <unordered_set>

#include "json.h"

// #define ONLY_C_LOCALE 1
// #include <date/date.h>

using namespace wlidsvc;
using namespace wlidsvc::net;
using namespace wlidsvc::storage;

DWORD CheckForUpdatesThreadProc(LPVOID lpParam)
{
    Sleep(5000);

    // auto is_valid_puid = [](int64_t puid, bool is_device) -> bool
    // {
    //     if (is_device)
    //         return (puid & 0xFC00000000000000) == 0xFC00000000000000;

    //     return (puid & 0xffff000000000000) == 0;
    // };

    // token_store_t token_store{db_path()};
    // identity_store_t identity_store{db_path()};

    // std::vector<token_t> tokens;
    // std::copy(token_store.begin(), token_store.end(), std::back_inserter(tokens));

    // std::unordered_set<std::string> identities_with_invalid_ids{};
    // std::string device_id = util::wstring_to_utf8(config::device_id());

    // for (const auto &token : tokens)
    // {
    //     LOG("Token in store - Identity: %s, Service: %s, Type: %s, Expires: %s",
    //         token.identity.c_str(),
    //         token.service.c_str(),
    //         token.type.c_str(),
    //         token.expires.c_str());

    //     identity_t id;
    //     if (!identity_store.retrieve(token.identity, id))
    //     {
    //         LOG("Token missing identity! Deleting... %s", token.identity.c_str());
    //         token_store.remove(token);

    //         continue;
    //     }

    //     if (token.service == "http://Passport.NET/tb")
    //         continue;

    //     if (identities_with_invalid_ids.find(id.identity) != identities_with_invalid_ids.end())
    //     {
    //         LOG("Token for service %s, identity %s, associated with invalid PUID, requiring reset.", token.service.c_str(), token.identity.c_str());
    //         token_store.mark_invalid(token.identity, token.service);
    //         continue;
    //     }

    //     const bool is_device = device_id == id.identity;
    //     if (!is_valid_puid(id.puid, is_device))
    //     {
    //         LOG("Token for service %s, identity %s, associated with invalid PUID, requiring reset.", token.service.c_str(), token.identity.c_str());
    //         token_store.mark_invalid(token.identity, token.service);
    //         identities_with_invalid_ids.emplace(id.identity);
    //     }
    // }

    return 0;
}