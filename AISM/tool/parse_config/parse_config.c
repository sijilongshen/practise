#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "parse_config.h"
#include "global_errno.h"
#include "debug.h"

// 从传入文件中获取配置对 放到结构体中
int Config_Init(const char* file_name, t_config_info* config)
{
    int                 ret = 0;
    int                 len = 0;
    int                 index = 0;
    FILE*               conf_file = NULL;
    char                line[512] = {0};
    char*               buffer = NULL;
    char*               key = NULL;
    char*               value = NULL; 
    char*               p = NULL;
    t_conf_node*        one_conf = NULL;
    
    if ( access(file_name, R_OK) != 0 )
    {
        ret = FILE_NOT_EXISTS;
        goto finish;
    }

    if( (conf_file = fopen(file_name, "r")) == NULL )
    {
        ret = OPEN_FILE_FAILED;
        goto finish;
    }else{
        fseek(conf_file, 0L, SEEK_SET);
    }

    //  初始化该结构体
    config->cur_config_len = 0;
    for (index=0; index<MAX_CONFIG_LIST_LEN; index ++)
    {
        config->arr_config_list[index] = NULL;
    }

    while(fgets(line, sizeof(line)-1, conf_file) != NULL)
    {
        // 去除左右空格
        buffer = remove_left_space(line);
        buffer = remove_right_space(buffer);
        
        level_print("get line =+++%s+++\n", buffer);

        // 注释或空行
        if((buffer[0] == '#') || buffer[0] == '\n')
        {
            level_print("this line is annotation or blank lines\n", buffer);
            continue;
        }

        // 清除回车
        len = (int)strlen(buffer);
        if( buffer[len-1] == '\n') 
            buffer[len-1] = '\0'; 

        // 是否是正常的 key = value
        if( (p = strchr(buffer, '=')) == NULL || p == buffer )
        {
            level_print("not find key '='\n", buffer);
            continue; 
        }

        // 获得key 和 value信息
        key = (char*)malloc((int)(p-buffer)+1);
        value = (char*)malloc(strlen(p)+1);
        if ( key == NULL || value == NULL)
        {
            ret = MALLOC_FAILED;
            goto finish;
        }
        strncpy(key, buffer, p - buffer );
        key = remove_left_space(key);
        key = remove_right_space(key);

        p ++;
        strncpy(value, p, strlen(p));
        value = remove_left_space(value);
        value = remove_right_space(value);

        if (strlen(key) == 0 || strlen(value) == 0 )
        {
            level_print("not get key info or value info", buffer);
            continue;
        }

        // 初始化结构体
        if ( (one_conf = (t_conf_node*)malloc(sizeof(t_conf_node))) == NULL )
        {
            ret = MALLOC_FAILED;
            goto finish;
        }else{
            level_print("cur_config_len=%d,key=%s,value=%s\n", config->cur_config_len, key, value);

            one_conf->key = key;
            one_conf->value = value;

            // 放到配置结构体
            config->arr_config_list[config->cur_config_len] = one_conf;
            config->cur_config_len ++;
            key = NULL;
            value = NULL;
        }
    } 
finish:
    if ( key )
        free(key);
    if ( value )
        free(value);
    if ( conf_file != NULL)
    {
        fclose(conf_file);
        conf_file = NULL;
    }
    if ( ret != 0 )
    {
        // 尝试释放结构体
        if ( config->cur_config_len != 0 )
            Config_Destory(config);
    }
    
    return ret;
}

int Config_Destory(t_config_info* config)
{
    int ret = 0;
    int i = 0;
    t_conf_node *tmp_conf_node = NULL;

    if (  config == NULL )
    {
        return PARAM_ERROR;
    }else{
        for ( i=0; i< config->cur_config_len; i ++ )
        {
            tmp_conf_node = config->arr_config_list[i];
            if ( tmp_conf_node->key != NULL )
                free(tmp_conf_node->key);
            if ( tmp_conf_node->value != NULL )
                free(tmp_conf_node->value);
        }
    }
    return 0;
}

int Config_GetValue(t_config_info* config, const char* key, char* value, int value_max_len)
{
    int ret = 0;
    int i = 0;
    t_conf_node *tmp_conf_node = NULL;

    if (  config == NULL || key == NULL )
    {
        return PARAM_ERROR;
    }else{
        for ( i=0; i< config->cur_config_len; i ++ )
        {
            tmp_conf_node = config->arr_config_list[i];
            if ( tmp_conf_node->key != NULL )
            {
                if ( strlen(tmp_conf_node->key) == strlen(key) && strncmp(tmp_conf_node->key, key, strlen(key)) == 0 )
                {
                    if ( strlen(tmp_conf_node->value) < value_max_len )
                    {
                        strncpy(value, tmp_conf_node->value, strlen(tmp_conf_node->value));
                        return 0;
                    }else{
                        return PARAM_IS_TOO_SHORT;
                    }
                }
            }
        }
    }
    return NOT_EXPECT_VALUE;
}

int Config_ShowList(t_config_info* config)
{
    int ret = 0;
    int i = 0;
    t_conf_node *tmp_conf_node = NULL;

    if (  config == NULL )
    {
        return PARAM_ERROR;
    }else{
        for ( i=0; i< config->cur_config_len; i ++ )
        {
            tmp_conf_node = config->arr_config_list[i];
            if ( tmp_conf_node->key != NULL )
                printf("%-16s = ", tmp_conf_node->key);
            if ( tmp_conf_node->value != NULL )
                printf("+++%s+++\n", tmp_conf_node->value);
        }
    }
    return 0;
}

// 去除字符串右侧的空格
char* remove_left_space(char *s)   
{   
    int l;   
    for(l=strlen(s); l > 0 && isspace(s[l-1]); l--)  
        s[l-1]='\0';   
    return s;   
}   

// 去除字符串左侧的空格
char* remove_right_space(char *s)   
{   
    char *p;  

    for(p=s; isspace(*p); p++)
        ;   
    if(p != s)     
        strcpy(s, p);
    return s;   
}

// 字符串小写化
char* conf_strlwr(char* str) 
{ 
    char*  orig = str; 
    for(; *str != '\0'; str++) 
        *str = tolower(*str); 
    return orig; 
}

