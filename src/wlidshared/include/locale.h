#ifndef UNDER_CE
#include_next <locale.h>
#else
#pragma once

typedef struct
{
    const char *decimal_point;
    const char *thousands_sep;
} lconv;

#ifdef __cplusplus
extern "C"
{
#endif
    lconv *localeconv();
#ifdef __cplusplus
}
#endif
#endif // _UNDER_CE