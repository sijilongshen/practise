#ifndef _DUMP_H_
#define _DUMP_H_
#include <stdio.h>
#include "dbfw_global.h"
#include "ip2.h"

void create_acp(FILE *fd);
void Npc_Dump(FILE *fd, uint8_t *data, int len);

#endif



