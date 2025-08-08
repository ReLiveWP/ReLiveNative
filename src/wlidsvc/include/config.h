#pragma once
#include <windows.h>
#include <string>

namespace wlidsvc::config
{
    template <typename T>
    struct config_result_t
    {
        inline config_result_t(HRESULT hr, T val) : _hr(hr), _val(val) {}

        const inline bool ok() const
        {
            return SUCCEEDED(hr());
        }

        const inline HRESULT hr() const
        {
            return _hr;
        }

        const inline T &value() const
        {
            return _val;
        }

    private:
        HRESULT _hr;
        T _val;
    };

    template <typename T>
    static const inline config_result_t<T> result(T t)
    {
        return {S_OK, t};
    }

    template <typename T>
    static const inline config_result_t<T> error(HRESULT hr)
    {
        return {hr, {}};
    }

    enum class environment_t
    {
        production = 0,
        internal
    };

    const config_result_t<environment_t> environment();
    const config_result_t<std::string> log_endpoint();

}