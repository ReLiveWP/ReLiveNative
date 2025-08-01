#pragma once
#include "globals.h"
#include <windows.h>
#include "ceimp.h"

namespace wlidsvc::util
{
    class critsect_t
    {
    public:
        inline critsect_t(LPCRITICAL_SECTION cs) : m_cs(cs) { EnterCriticalSection(m_cs); }
        inline ~critsect_t() { LeaveCriticalSection(m_cs); }

    private:
        LPCRITICAL_SECTION m_cs;
    };

    class hkey_t
    {
    public:
        hkey_t() noexcept = default;
        inline explicit hkey_t(HKEY hkey) noexcept : handle_(hkey) {}
        inline hkey_t(hkey_t &&other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }
        inline hkey_t &operator=(hkey_t &&other) noexcept
        {
            if (this != &other)
            {
                reset();
                handle_ = other.handle_;
                other.handle_ = nullptr;
            }
            return *this;
        }

        hkey_t(const hkey_t &) = delete;
        hkey_t &operator=(const hkey_t &) = delete;

        ~hkey_t()
        {
            reset();
        }

        void attach(HKEY hkey) noexcept
        {
            reset();
            handle_ = hkey;
        }

        HKEY detach() noexcept
        {
            HKEY temp = handle_;
            handle_ = nullptr;
            return temp;
        }

        void reset() noexcept
        {
            if (handle_)
            {
                RegCloseKey(handle_);
                handle_ = nullptr;
            }
        }

        HKEY get() const noexcept { return handle_; }
        HKEY *put() noexcept
        {
            reset();
            return &handle_;
        }
        explicit operator bool() const noexcept { return handle_ != nullptr; }

    private:
        HKEY handle_ = nullptr;
    };

    // so this is fun
    // all these Ce* functions seem to be completely undocumented :D
    class impersonate_t
    {
    public:
        inline impersonate_t() = default;

        inline HRESULT impersonate()
        {
            auto ret = S_OK;
            auto isThreadImpersonated = (DWORD_PTR)TlsGetValue(globals::g_tlsIsImpersonatedIdx);
            if (isThreadImpersonated == 0 && (GetLastError() == 0))
            {
                if (!CeImpersonateCurrentProcess())
                {
                    ret = HRESULT_FROM_WIN32(GetLastError());
                    goto end;
                }
            }

            TlsSetValue(globals::g_tlsIsImpersonatedIdx, (LPVOID)(++isThreadImpersonated));

        end:
            return ret;
        }

        inline HRESULT verify_policy(LPCWSTR lpszPolicyName = TEXT("WLIDSVC"))
        {
            if (!CePolicyCheckWithContext(NULL, lpszPolicyName, 0, 0x43, 0x80000000, 0, 0))
            {
                return HRESULT_FROM_WIN32(GetLastError());
            }

            return S_OK;
        }

        inline ~impersonate_t()
        {
            auto isThreadImpersonated = (DWORD_PTR)TlsGetValue(globals::g_tlsIsImpersonatedIdx);
            if (isThreadImpersonated == 1)
            {
                CeRevertToSelf();
            }
            else if (isThreadImpersonated == 0)
            {
                return;
            }

            TlsSetValue(globals::g_tlsIsImpersonatedIdx, (LPVOID)(--isThreadImpersonated));
        }
    };
}