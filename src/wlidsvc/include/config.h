#pragma once
#include <windows.h>
#include <string>

namespace wlidsvc::config
{
    const HRESULT init_client_config(void);
    const std::wstring client_config_db_path();

    enum class environment_t
    {
        production = 0,
        internal
    };

    const environment_t environment();
    const std::string log_endpoint();

    const std::wstring default_id();
}