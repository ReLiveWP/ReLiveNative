#include "nanoprintf.h"

namespace wlidsvc::util
{
    class critsect_t
    {
    public:
        critsect_t(LPCRITICAL_SECTION cs) : m_cs(cs) { EnterCriticalSection(m_cs); }
        ~critsect_t() { LeaveCriticalSection(m_cs); }

    private:
        LPCRITICAL_SECTION m_cs;
    };
}