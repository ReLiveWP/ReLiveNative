#pragma once

#include <array>
#include <atomic>
#include <algorithm>
#include <windows.h>
#include <cstring>

typedef void CURL;

#ifndef STRINGIZE
#define STRINGIZE(x) STRINGIZE2(x)
#define STRINGIZE2(x) #x
#endif

#define LINE_STRING STRINGIZE(__LINE__)
#define LOG(fmt, ...) wlidsvc::log::info().log(__FILE__ ":" LINE_STRING " " fmt, __VA_ARGS__)
#define LOG_WIDE(fmt, ...) wlidsvc::log::info().log(TEXT(__FILE__) L":" TEXT(LINE_STRING) L" " fmt, __VA_ARGS__)

#define VALIDATE_PARAMETER(x)                                                        \
    if ((x))                                                                         \
    {                                                                                \
        wlidsvc::log::info().log(__FILE__ " " LINE_STRING " ASSERTION FAILED: " #x); \
        return E_INVALIDARG;                                                         \
    }

#define WINDOWS_TICK 10000000
#define SEC_TO_UNIX_EPOCH 11644473600LL
static inline __time64_t filetime_to_time(const FILETIME &ft)
{
    long long secs = ((*(LONGLONG *)&(ft)) / WINDOWS_TICK) - SEC_TO_UNIX_EPOCH;
    __time64_t t = (__time64_t)secs;
    return t;
}

static inline char *wchar_to_char(const wchar_t *fmt)
{
    // codecvt bloats the binary size by i shit you not over 500kb
    size_t length = ::wcslen(fmt);
    int dwLength = WideCharToMultiByte(CP_UTF8, 0, fmt, length, NULL, 0, NULL, NULL);

    char *tmp = new (std::nothrow) char[dwLength + 1];
    if (tmp == nullptr)
        return nullptr;
        
    WideCharToMultiByte(CP_UTF8, 0, fmt, length, tmp, dwLength, NULL, NULL);
    tmp[dwLength] = '\0';

    return tmp;
}

namespace wlidsvc::log
{
    struct logmsg_t
    {
    public:
        logmsg_t()
        {
            this->size_ = 0;
            this->data_ = nullptr;
            this->ts_ = 0;
        }

        logmsg_t(const char *msg)
        {
            this->size_ = std::strlen(msg) + 1;
            this->data_ = new char[size_];
            std::memcpy(data_, msg, size_ * sizeof(char));

            FILETIME ft;
            SYSTEMTIME st;

            GetSystemTime(&st);
            SystemTimeToFileTime(&st, &ft);

            this->ts_ = filetime_to_time(ft);
        }

        logmsg_t(const logmsg_t &other)
        {
            this->ts_ = other.ts_;
            this->size_ = other.size_;
            this->data_ = new char[this->size_];
            std::memcpy(this->data_, other.data_, this->size_ * sizeof(char));
        }

        logmsg_t(logmsg_t &&other) // string&& is an rvalue reference to a string
        {
            size_ = other.size_;
            ts_ = other.ts_;
            data_ = other.data_;
            other.size_ = 0;
            other.ts_ = 0;
            other.data_ = nullptr;
        }

        logmsg_t &operator=(logmsg_t other)
        {
            std::swap(data_, other.data_);
            std::swap(size_, other.size_);
            std::swap(ts_, other.ts_);
            return *this;
        }

        ~logmsg_t()
        {
            if (data_ != nullptr)
                delete[] data_;
        }

        const __time64_t ts() const
        {
            return ts_;
        }

        const size_t size() const
        {
            return size_;
        }

        const char *data() const
        {
            return data_;
        }

    private:
        __time64_t ts_;
        size_t size_;
        char *data_;
    };

    template <size_t Size>
    class logqueue_t
    {
    public:
        logqueue_t()
            : head_(0), tail_(0), buffer_()
        {
        }

        bool enqueue(const logmsg_t &item)
        {
            size_t tail = tail_.fetch_add(1, std::memory_order_acq_rel);
            if (tail - head_.load(std::memory_order_acquire) >= Size)
                return false;

            buffer_[tail % Size] = item;
            return true;
        }

        bool dequeue(logmsg_t &item)
        {
            size_t head = head_.load(std::memory_order_relaxed);
            if (tail_.load(std::memory_order_acquire) == head)
                return false;

            item = buffer_[head % Size];
            head_.store(head + 1, std::memory_order_release);
            return true;
        }

    private:
        std::array<logmsg_t, Size> buffer_;
        std::atomic<size_t> head_;
        std::atomic<size_t> tail_;
    };

    enum class logger_thread_state_t
    {
        uninitialized,
        connected,
        disconnected,
        cleanup
    };

    class logger_t
    {
    public:
        inline logger_t()
            : queue_(),
              hThread_(NULL),
              state_(logger_thread_state_t::uninitialized),
              curl_(NULL)
        {
            InitializeCriticalSection(&init_cs);
        }

        void log(const char *msg, ...);
        void log(const wchar_t *msg, ...);

    private:
        void init();
        void log_real(const char *fmt, va_list args);

        static DWORD thread_proc(IN LPVOID lpParameter);

        logqueue_t<250> queue_;
        HANDLE hThread_;
        logger_thread_state_t state_;
        CRITICAL_SECTION init_cs;

        CURL *curl_;
    };

    extern logger_t &info();
}