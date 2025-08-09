#include "log.h"
#include "util.h"
#include "config.h"
#include "nanoprintf.h"

#include <string>

#include <cerrno>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace wlidsvc::log
{
    static logger_t _info{};
    logger_t &info()
    {
        return _info;
    }

    void logger_t::log(const char *fmt, ...)
    {
        va_list args1;
        va_start(args1, fmt);

        log_real(fmt, args1);
        va_end(args1);
    }

    void logger_t::log(const wchar_t *fmt, ...)
    {
        va_list args1;
        va_start(args1, fmt);

        char *tmp = wchar_to_char(fmt);

        log_real(tmp, args1);
        va_end(args1);

        delete[] tmp;
    }

    void logger_t::log_real(const char *fmt, va_list args1)
    {
        va_list args2;
        va_copy(args2, args1);

        size_t size = 1 + npf_vsnprintf(nullptr, 0, fmt, args1);

        char *buffer = new char[size];
        npf_vsnprintf(buffer, size, fmt, args2);
        va_end(args2);

#ifndef UNDER_CE
        OutputDebugStringA(buffer);
        OutputDebugStringA("\n");
#endif

        init();
        queue_.enqueue({buffer});

        delete[] buffer;
    }

    void logger_t::init()
    {
        util::critsect_t cs(&init_cs);

        if (hThread_ == nullptr)
        {
            hThread_ = CreateThread(NULL, 0, &logger_t::thread_proc, this, 0, NULL);
        }
    }

    DWORD logger_t::thread_proc(IN LPVOID lpParameter)
    {
        logger_t *self = (logger_t *)lpParameter;
        CURLcode res{};

        while (true)
        {
            switch (self->state_)
            {
            case logger_thread_state_t::uninitialized:
            {
                self->log("Initializing logger...");

                self->curl_ = curl_easy_init();
                if (!self->curl_)
                    break;

                auto log_endpoint = config::log_endpoint();
                curl_easy_setopt(self->curl_, CURLOPT_URL, log_endpoint.c_str());
                curl_easy_setopt(self->curl_, CURLOPT_CONNECT_ONLY, 2L);

                res = curl_easy_perform(self->curl_);
                if (res == CURLE_OK)
                {
                    self->log("Logger connected to websocket!");
                    self->state_ = logger_thread_state_t::connected;
                }
                else
                {
                    self->log("Logger failed to connect! %s", curl_easy_strerror(res));
                    self->state_ = logger_thread_state_t::cleanup;
                }

                break;
            }
            case logger_thread_state_t::connected:
            {
                logmsg_t msg;
                while (self->queue_.dequeue(msg))
                {
                    json j;
                    j["t"] = msg.ts();
                    j["m"] = std::string(msg.data());
                    auto str = j.dump();

                    size_t sent, buflen = str.size();
                    const char *buf = str.c_str();

                    res = curl_ws_send(self->curl_, buf, buflen, &sent, 0, CURLWS_TEXT);
                    if (!res)
                    {
                        buf += sent;
                        buflen -= sent;
                    }
                    else if (res == CURLE_AGAIN)
                    {
                        Sleep(500); // better ways to do this
                    }
                    else
                    {
                        self->log("Logger failed to send! %s", curl_easy_strerror(res));
                        self->state_ = logger_thread_state_t::cleanup;
                        break;
                    }
                }

                Sleep(5000);
                break;
            }
            case logger_thread_state_t::cleanup:
            {
                Sleep(5000);
                self->log("Resetting logger...");

                if (self->curl_ != NULL)
                    curl_easy_cleanup(self->curl_);

                self->state_ = logger_thread_state_t::uninitialized;
                break;
            }
            default:
                break;
            }
        }

        return 0;
    }
}