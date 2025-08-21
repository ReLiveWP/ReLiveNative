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
    static constexpr const char *g_requestTokensEndpoint = "https://login.relivewp.net/auth/request_tokens";
    static constexpr const char *g_provisionDeviceEndpoint = "https://login.relivewp.net/auth/provision_device";
#else
    static constexpr const char *g_requestTokensEndpoint = "http://login.int.relivewp.net/auth/request_tokens";
    static constexpr const char *g_provisionDeviceEndpoint = "http://login.int.relivewp.net/auth/provision_device";
#endif
}
