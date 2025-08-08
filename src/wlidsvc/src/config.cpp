
#include <windows.h>
#include "config.h"
#include "storage.h"
#include "util.h"
#include "log.h"

#include <string>

using namespace wlidsvc::util;
using namespace wlidsvc::storage;

namespace wlidsvc::config
{
    const environment_t environment()
    {
#ifdef IS_PRODUCTION_BUILD
        return environment_t::production;
#else
        return environment_t::internal;
#endif
    }

    static const std::string log_endpoint_default = "ws://172.16.0.2:5678/";
    const std::string log_endpoint()
    {
        config_store_t cs{db_path()};
        return cs.get("LogEndpoint", log_endpoint_default);
    }

    const std::wstring default_id()
    {
        config_store_t cs{db_path()};
        return utf8_to_wstring(cs.get("DefaultID"));
    }
}