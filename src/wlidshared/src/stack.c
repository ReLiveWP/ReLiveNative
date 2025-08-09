#include <windows.h>

void *__stack_chk_guard = (void *)0xdeadbeef;

void __stack_chk_fail(void)
{
    TerminateProcess(GetCurrentProcess(), HRESULT_FROM_WIN32(ERROR_STACK_BUFFER_OVERRUN));
}
