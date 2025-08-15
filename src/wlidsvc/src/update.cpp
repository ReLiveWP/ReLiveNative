#include "update.h"
#include "log.h"
#include "microrest.h"

#include <cerrno>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

using namespace wlidsvc::net;

DWORD CheckForUpdatesThreadProc(LPVOID lpParam)
{
    return 0;
}