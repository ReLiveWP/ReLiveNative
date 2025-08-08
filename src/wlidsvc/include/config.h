#pragma once
#include <windows.h>
#include <string>

namespace wlidsvc::config
{
    enum class environment_t
    {
        production = 0,
        internal
    };

    const environment_t environment();
    const std::string log_endpoint();

    const std::wstring default_id();
}