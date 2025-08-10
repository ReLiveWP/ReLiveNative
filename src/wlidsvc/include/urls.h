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
#ifdef UNDER_CE
    static constexpr const char *g_clientConfigEndpoint = "https://relive.wamwoowam.co.uk/config";
    static constexpr const char *g_clientConfigVersionEndpoint = "https://relive.wamwoowam.co.uk/config/version";
#else
    static constexpr const char *g_clientConfigEndpoint = "http://localhost:5012/config_int";
    static constexpr const char *g_clientConfigVersionEndpoint = "http://localhost:5012/config/version";
#endif
    static constexpr const char *g_endpointRequestSecurityTokens = "Endpoint:RequestSecurityTokens";
}