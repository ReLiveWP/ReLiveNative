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