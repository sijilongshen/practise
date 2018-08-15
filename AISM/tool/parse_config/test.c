#include <stdio.h>

#include "parse_config.h"

int main()
{
    // 测试程序 需要测试配置文件 a.cnf
    const char* conf_file = "./a.cnf";
    char value[512] = {0};
    int ret = 0;
    t_config_info global_config;

    ret = Config_Init(conf_file, &global_config);
    printf("ret = %d\n", ret);

    ret = Config_GetValue(&global_config, "day_value", value, sizeof(value));
    printf("value = %s, ret = %d\n", value, ret);

    ret = Config_ShowList(&global_config);
    printf("ret = %d\n", ret);

    ret = Config_Destory(&global_config);
    printf("ret = %d\n", ret);

    return 0;
}

