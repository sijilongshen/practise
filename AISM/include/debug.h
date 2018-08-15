#include <stdarg.h>
#include <stdio.h>

#ifdef DEBUG_SWITCH
int debug_level=1;
#else
int debug_level = 0;
#endif

//  打印调试信息
void level_print(const char *fmt, ...)
{
    va_list arglist;

    if((debug_level) >= 1)
    {
        va_start(arglist, fmt);
        vfprintf(stdout, fmt, arglist);
        va_end(arglist);
    }
}


