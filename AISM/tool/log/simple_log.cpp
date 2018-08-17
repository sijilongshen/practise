#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include "simple_log.h"

#ifndef MAX_LOG_FILE_SIZE
#define MAX_LOG_FILE_SIZE (8*1024*1024) 
#endif

// global file handle
FILE*           __fh_logfile=NULL;
char            __procees_name[16]={0};

void Time2Str(time_t time1, char *szTime)
{
    struct tm tm1;
    localtime_r(&time1, &tm1 );
    sprintf( szTime, "%4.4d%2.2d%2.2d%2.2d%2.2d%2.2d",
        tm1.tm_year+1900, tm1.tm_mon+1, tm1.tm_mday,
        tm1.tm_hour, tm1.tm_min,tm1.tm_sec);
}

void Time2Str_Format(time_t time1, char *szTime)
{
    struct tm tm1;
    localtime_r(&time1, &tm1 );
    sprintf( szTime, "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d",
        tm1.tm_year+1900, tm1.tm_mon+1, tm1.tm_mday,
        tm1.tm_hour, tm1.tm_min,tm1.tm_sec);
}

static FILE* SqlErrorOpenLogFile(const char *pLogFileName)
{
    const char *pOpenMode = "wb";
    struct stat statbuff;

    memset(&statbuff, 0x00, sizeof(statbuff));
    if (access(pLogFileName, F_OK) == 0)
    {
        if(stat(pLogFileName, &statbuff) < 0){  
            pOpenMode = "a";
        }else{  
            if (statbuff.st_size >= MAX_LOG_FILE_SIZE)
            {
                time_t currTime = time(NULL);
                char szTimeStr[16] = {0};
                Time2Str(currTime, szTimeStr);
                char szNewName[256];
                snprintf(szNewName, sizeof(szNewName), "%s_%s", pLogFileName, szTimeStr);
                rename(pLogFileName, szNewName);
            }
            else
            {
                pOpenMode = "a";
            }
        }
    }else{
        pOpenMode = "a";
    }

    return fopen(pLogFileName, pOpenMode);
}
int SqlError_InitLogfile(char *dbfw_base_path, const char *process_full_name)
{
    char log_path[128]={0};
    const char *p_tmp = NULL;
    char this_sqlerror_logfile[128]={0};

    p_tmp = rindex((const char*)process_full_name, '/');
    if ( p_tmp == NULL)
    {
        return -1; 
    }else{
        strcpy(__procees_name, p_tmp+1);
    }

    sprintf(log_path, "%s%s%s", dbfw_base_path, "pdump/", __procees_name);
    if (access(log_path, F_OK) != 0 )
    {
        mkdir(log_path, 0775);    
    }
    sprintf(log_path, "%s%s", log_path, "/sync/");
    if (access(log_path, F_OK) != 0 )
    {
        mkdir(log_path, 0775);    
    }
    /* /dbfw_capbuf/pdump/procees_name/sqlerror/logname */
    snprintf(this_sqlerror_logfile, sizeof(this_sqlerror_logfile), "%s%s%s", log_path, __procees_name, "_sqlerror");
    if (NULL == (__fh_sqlerror_logfile=SqlErrorOpenLogFile(this_sqlerror_logfile)))
    {
        return -1;
    }

    //SqlError_LogInfo("--------------start-----------------1");
    return 1;
}

int SqlError_LogInfo(const char* msg, unsigned int err_no)
{
    if (__fh_sqlerror_logfile == NULL)
        return -1;

    int size = 0;
    time_t  ts;
    char    logstr[1024];
    char    cur_time[49];
    memset(logstr,0x00,sizeof(logstr));

    ts = time(NULL);
    Sqlerror_Time2Str_Format(ts,(char*)cur_time);
    sprintf(logstr, "[INFO]%s\t%s:%d\n%s",(char*)cur_time,__procees_name,err_no,msg);
    size = strlen((char*)logstr);
    if(logstr[size-1]!='\n')
    {
        logstr[size] = '\n';
    }
    fwrite(logstr, strlen(logstr), 1, __fh_sqlerror_logfile);
    fflush(__fh_sqlerror_logfile);
    return 1;
}

void SqlError_CloseLogfile(void)
{
    if(__fh_sqlerror_logfile)
    {
        fclose(__fh_sqlerror_logfile);
        __fh_sqlerror_logfile = NULL;
    }
}

