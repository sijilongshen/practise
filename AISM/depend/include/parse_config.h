#ifndef __PARAM_CONFIG_C__

#ifndef MAX_CONFIG_LIST_LEN
#define MAX_CONFIG_LIST_LEN 1024
#endif

//  每个配置对的信息
typedef struct t_conf_node{
    char*               key;                                        // 配置对的key
    char*               value;                                      // 配置对的value
}t_conf_node;

typedef struct t_config_info{
    int                 cur_config_len;                             // 保存了多少个配置对
    t_conf_node*        arr_config_list[MAX_CONFIG_LIST_LEN];       // 保存配置对地址的数组 
}t_config_info;

int Config_Init(const char* file_name, t_config_info* config);
int Config_Destory(t_config_info* config);
int Config_GetValue(t_config_info* config, const char* key, char* value, int value_max_len);
int Config_ShowList(t_config_info* config);

char* remove_left_space(char *s);
char* remove_right_space(char *s);
#endif
