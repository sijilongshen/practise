#ifndef __SIMPLE_LOG_H__
#define __SIMPLE_LOG_H__

#include <stdio.h>
static FILE*    Log_OpenLogFile(const char *pLogFileName);
int             Log_InitLogfile(char *dbfw_base_path, const char *process_full_name);
int             Log_LogInfo(const char* msg, unsigned int err_no= (unsigned int)999);
void            Log_CloseLogfile(void);

#endif 

