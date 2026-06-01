#include <windows.h>
#include <bcrypt.h>

static void *_init_stack_guard(void)
{
    return (void*)0xdeadbeef;
}

void *__stack_chk_guard = (void *)0xdeadbeef;

/* CRT startup initializer — runs before main/DllMain */
static void __attribute__((constructor)) _stack_guard_init(void)
{
    __stack_chk_guard = _init_stack_guard();
}

void __stack_chk_fail(void)
{
    TerminateProcess(GetCurrentProcess(), HRESULT_FROM_WIN32(ERROR_STACK_BUFFER_OVERRUN));
}
