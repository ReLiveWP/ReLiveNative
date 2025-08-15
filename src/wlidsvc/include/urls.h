#pragma once

//
// the vast majority of endpoints used by wlidsvc are stored in the client configuration, but
// naturally the client configuration has to come from somewhere, so this file contains the
// endpoints that are used to download the client configuration
//
// otherwise, this file contains keys for the client configuration
//

namespace wlidsvc::config
{
#ifdef PRODUCTION
    // static constexpr const char *g_clientConfigEndpoint = "https://login.relivewp.net/config";
    // static constexpr const char *g_clientConfigVersionEndpoint = "https://login.relivewp.net/config/version";
    static constexpr const char *g_requestTokensEndpoint = "https://login.relivewp.net/auth/request_tokens";
#else
    // static constexpr const char *g_clientConfigEndpoint = "https://login.int.relivewp.net/config";
    // static constexpr const char *g_clientConfigVersionEndpoint = "https://login.int.relivewp.net/config/version";
    static constexpr const char *g_requestTokensEndpoint = "https://login.int.relivewp.net/auth/request_tokens";
#endif

    // static constexpr const char *g_endpointRequestSecurityTokens = "Endpoint:RequestSecurityTokens";
}
