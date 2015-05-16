#include <stdlib.h>
#include <errno.h>
#include "config.h"
#include "npc_util.h"
#include "dbfw_log.h"

#define __USE_GNU
#include <sched.h>
#include <ctype.h>

time_t log_time;

void Npc_Ip2Str(u_int ip, u_char str[])
{	
	u_int val, k;	
	int i=0;	
	int greater_hundred=0;
	val=(ip>>24)&0xFF;	
	if((k=val/100)>0)
	{
		str[i++]=k+'0';		
		greater_hundred = 1;
	}
	if((k=val%100/10)>0 || greater_hundred==1)
	{
		str[i++]=k+'0';	
	}
	str[i++]=val%10+'0';	
	str[i++]='.';	

	greater_hundred=0;
	val=(ip>>16)&0xFF;        
	if((k=val/100)>0)
	{
		str[i++]=k+'0'; 
		greater_hundred = 1;
	}
	if((k=val%100/10)>0 || greater_hundred==1)
	{
		str[i++]=k+'0';   
	}

	str[i++]=val%10+'0';	
	str[i++]='.';		

	greater_hundred=0;
	val=(ip>>8)&0xFF;        
	if((k=val/100)>0)
	{
		str[i++]=k+'0';      
		greater_hundred = 1;
	}
	if((k=val%100/10)>0 || greater_hundred==1)
	{
		str[i++]=k+'0';
	}
	str[i++]=val%10+'0';	
	str[i++]='.';	

	greater_hundred=0;
	val=ip&0xFF;        
	if((k=val/100)>0)
	{
		str[i++]=k+'0';   
		greater_hundred = 1;
	}
	if((k=val%100/10)>0 || greater_hundred==1)
	{
		str[i++]=k+'0'; 
	}
	str[i++]=val%10+'0';	
	str[i]='\0';
}


void Npc_FormatMacAddress(const u_char *p_mac, u_char mac[])
{
	static u_char hex[16]={'0', '1', '2', '3', '4', '5', '6', '7', 
		'8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
	int val;
	val = ((*p_mac>>4)&0x0F);
	mac[0]=hex[val];
	val = ((*p_mac)&0x0F);
	mac[1]=hex[val];
	mac[2]=':';
	++p_mac;

	val = ((*p_mac>>4)&0x0F);
	mac[3]=hex[val];
	val = ((*p_mac)&0x0F);
	mac[4]=hex[val];
	mac[5]=':';
	++p_mac;

	val = ((*p_mac>>4)&0x0F);
	mac[6]=hex[val];
	val = ((*p_mac)&0x0F);
	mac[7]=hex[val];
	mac[8]=':';
	++p_mac;

	val = ((*p_mac>>4)&0x0F);
	mac[9]=hex[val];
	val = ((*p_mac)&0x0F);
	mac[10]=hex[val];
	mac[11]=':';
	++p_mac;

	val = ((*p_mac>>4)&0x0F);
	mac[12]=hex[val];
	val = ((*p_mac)&0x0F);
	mac[13]=hex[val];
	mac[14]=':';
	++p_mac;

	val = ((*p_mac>>4)&0x0F);
	mac[15]=hex[val];
	val = ((*p_mac)&0x0F);
	mac[16]=hex[val];
	mac[17]='\0';

}

void Npc_FormatMacAddress_Clear(const u_char *p_mac, u_char mac[])
{
    static u_char hex[16]={'0', '1', '2', '3', '4', '5', '6', '7', 
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    int val;
    val = ((*p_mac>>4)&0x0F);
    mac[0]=hex[val];
    val = ((*p_mac)&0x0F);
    mac[1]=hex[val];
    //mac[2]=':';
    ++p_mac;

    val = ((*p_mac>>4)&0x0F);
    mac[2]=hex[val];
    val = ((*p_mac)&0x0F);
    mac[3]=hex[val];
    //mac[5]=':';
    ++p_mac;

    val = ((*p_mac>>4)&0x0F);
    mac[4]=hex[val];
    val = ((*p_mac)&0x0F);
    mac[5]=hex[val];
    //mac[8]=':';
    ++p_mac;

    val = ((*p_mac>>4)&0x0F);
    mac[6]=hex[val];
    val = ((*p_mac)&0x0F);
    mac[7]=hex[val];
    //mac[11]=':';
    ++p_mac;

    val = ((*p_mac>>4)&0x0F);
    mac[8]=hex[val];
    val = ((*p_mac)&0x0F);
    mac[9]=hex[val];
    //mac[14]=':';
    ++p_mac;

    val = ((*p_mac>>4)&0x0F);
    mac[10]=hex[val];
    val = ((*p_mac)&0x0F);
    mac[11]=hex[val];
    //mac[17]='\0';
    mac[12]='\0';

}

u_int hasher1(u_int64 key, u_int prime)
{
	return key%prime;
}

u_int hasher2(u_int64 key)
{
	return  ((key&0x7ff)^
		((key>>11)&0x7ff)^
		((key>>22)&0x7ff)^
		((key>>33)&0x7ff))&0x7ff;
}

extern Dbfw_LogFile npc_log_file;
extern Dbfw_ErrorLog error_log;
extern Dbfw_DebugLog debug_log;
extern Dbfw_WarnLog warn_log;
extern Dbfw_InfoLog info_log;

/***********************************************
**
**
**	初始化缓冲池,将缓冲池中节点连接成一个链表
**
**
***********************************************/
void Npc_HashpoolInit(u_char *pool, u_int num_node)
{
	u_char *pre, *next;
	u_int i;
	pre = pool;
	next = pre + sizeof(Npc_HashNode);
	for(i=0;i<num_node-1;++i)
	{
		((Npc_HashNode*)pre)->_next = (Npc_HashNode*)next;
		pre = next;
		next = next + sizeof(Npc_HashNode);
	}
	((Npc_HashNode*)pre)->_next = NULL;
}

/******************************************************
**
**	从缓冲池中分配一个节点,如果没有可用的空闲节点,就分配失败
**  RETURN
**		>0: 分配的节点指针
**		NULL：分配失败
**
******************************************************/
Npc_HashNode* Npc_HashmapAllocNode(Npc_HashPool* hashpool)
{
	//u_char *new_pool;
	//Npc_HashNode **new_buckets;
	//Npc_HashNode *new_header;
	//Npc_HashNode *new_tmp;
	//int i;
	Npc_HashNode *tmp;
	if(hashpool->_header!=NULL)
	{
		tmp=hashpool->_header;
		hashpool->_header = hashpool->_header->_next;
	}
	else//if(hashpool->_header==NULL)
	{
		return NULL;
		/* allocate new pool */
		//      hashpool->_size = (hashpool->_size<<1);
		//      new_pool = (u_char*)malloc(hashpool->_size);
		//      if(new_pool==NULL)
		//      {
		//#ifdef NPC_LOG
		//         NPC_NEW_LOG(ERROR_LEVEL, error_log, "No enough memory can be allocated for hash pool.");
		//         DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
		//#endif
		//         return NULL;
		//      }
		//
		//      Npc_HashpoolInit(new_pool, hashpool->_num_element);
		//      new_header = (Npc_HashNode*)new_pool;
		//      /* new buckets' size is also NPC_HASHMAP_PRIME */
		//      new_buckets = (Npc_HashNode**)malloc(hashpool->_num_bucket * sizeof(Npc_HashNode*));
		//      memset(new_buckets, 0 , hashpool->_num_bucket * sizeof(Npc_HashNode*));
		//      /* copy key and value from old buckets to new buckets, new node is provided by new pool */
		//      for(i=0;i<hashpool->_num_bucket;++i)
		//      {
		//         for(tmp=hashpool->_buckets[i]; tmp; tmp=tmp->_next)
		//         {
		//            new_tmp = new_header;
		//            new_header = new_header->_next;
		//            
		//            new_tmp->_key = tmp->_key;
		//            new_tmp->_value = tmp->_value;
		//            new_tmp->_next = new_buckets[i];
		//            new_buckets[i] = new_tmp;
		//         }
		//      }
		//
		//      free(hashpool->_buckets);
		//      free(hashpool->_pool);
		//      
		//      hashpool->_pool = new_pool;
		//      hashpool->_buckets = new_buckets;
		//      hashpool->_header = new_header;
		//      
		//#ifdef NPC_LOG
		//      NPC_NEW_LOG(INFO_LEVEL, info_log, "Hash pool is increased to %d.", hashpool->_size);
		//      DBFW_INFO_PRINT(&npc_log_file, &info_log);
		//#endif
		//
		//      tmp = hashpool->_header;
		//      hashpool->_header = hashpool->_header->_next;
	}
	return tmp;
}
/*
*       put node back into hashpool
*/
void Npc_HashmapFreeNode(Npc_HashPool* hashpool, Npc_HashNode *node)
{
	node->_next = hashpool->_header;
	hashpool->_header = node;
}

/********************************
**
**	初始化Hashmap,
**	桶数量为5987,
**	内存池可容纳8192个元素
**
********************************/
int Npc_HashmapInit(Npc_HashPool* hashpool)
{
	hashpool->_pool = NULL;
	hashpool->_buckets = NULL;
	Npc_HashNode** buckets= (Npc_HashNode**)malloc(hashpool->_num_bucket * sizeof(Npc_HashNode*));
	if(buckets==NULL)
		return -1;
	memset(buckets, 0 , hashpool->_num_bucket * sizeof(Npc_HashNode*));

	u_char *pool = (u_char*)malloc(hashpool->_num_element * sizeof(Npc_HashNode));
	if(pool==NULL)
		return -1;
	Npc_HashpoolInit(pool, hashpool->_num_element);

	hashpool->_pool = pool;
	hashpool->_buckets = buckets;
	hashpool->_header = (Npc_HashNode*)pool;
	hashpool->_size = hashpool->_num_element * sizeof(Npc_HashNode);
	return 0;
}

/************************************************
**
**	将缓冲池清空,重新组织成一个链表
**	将buckets数组清空
**	RETURN
**		0:ok
**		-1:error
************************************************/
int Npc_HashmapReset(Npc_HashPool* hashpool)
{
	if(hashpool->_pool==NULL)
		return -1;
	memset(hashpool->_pool, 0x00, hashpool->_size);
	Npc_HashpoolInit((u_char*)hashpool->_pool, hashpool->_num_element);
	hashpool->_header = (Npc_HashNode*)hashpool->_pool;

	if(hashpool->_buckets==NULL)
		return -1;
	memset(hashpool->_buckets, 0x00, hashpool->_num_bucket * sizeof(Npc_HashNode*));
	return 0;
}
void Npc_HashmapDestroy(Npc_HashPool *hashpool)
{
	free(hashpool->_buckets);
	free(hashpool->_pool);
}

int Npc_HashmapInsert(Npc_HashPool* hashpool, u_int64 key, u_short value, int sem_id)
{    
#ifdef DEBUG_HASHMAP
	u_int count=0;
#endif

	u_int bucket_index;
	Npc_HashNode *p_first, *p_tmp, *p_cur;

	bucket_index = hasher1(key, hashpool->_num_bucket);
	p_first = hashpool->_buckets[bucket_index];

	for (p_cur = p_first; p_cur; p_cur = p_cur->_next)
	{ 
		if(p_cur->_key == key)
		{    
#ifdef DEBUG_HASHMAP
			printf("[Hashmap]: [Update] bucket_index:%u, key=0x%llx, value=%u -> %u, sem_id=%d -> %d\n", bucket_index, key, p_cur->_value, value, p_cur->_sem_id, sem_id, count+1);
#endif
			p_cur->_value = value;/*如果key已经存在，则更新value*/
			p_cur->_sem_id = sem_id;
			return p_cur->_value;
		}
#ifdef DEBUG_HASHMAP
		++count;
#endif
	}
#ifdef DEBUG_HASHMAP
	printf("[Hashmap]: [Insert] bucket_index:%u, key=0x%llx, value=%u, sem_id=%d, length=%u\n", bucket_index, key, value, sem_id, count+1);
#endif

	/*如果key不存在，则插入新的key->value*/
	p_tmp = Npc_HashmapAllocNode(hashpool);
	if(p_tmp==NULL)/* 缓冲池用光了 */
	{
		return -2;
	}
	p_tmp->_key = key;
	p_tmp->_value = value;
	p_tmp->_sem_id = sem_id;
	p_tmp->_next = hashpool->_buckets[bucket_index];
	hashpool->_buckets[bucket_index] = p_tmp;

	return -1;
}

u_short Npc_HashmapFind(Npc_HashPool* hashpool, u_int64 key)
{
	u_int bucket_index;
	Npc_HashNode *p_first, *p_cur;
	bucket_index = hasher1(key, hashpool->_num_bucket);
	p_first = hashpool->_buckets[bucket_index];

	for (p_cur = p_first; p_cur; p_cur = p_cur->_next)
	{ 
		if(p_cur->_key == key)
			return p_cur->_value;/*找到value值*/
	}
	return NPC_HASHMAP_NOT_FIND_KEY;/*没有找到*/
}
/*********************************************
**
**	删除key对应的节点,将节点回收到缓冲池里
**
*********************************************/
u_short Npc_HashmapDelete(Npc_HashPool *hashpool, u_int64 key)
{
	u_int bucket_index;
	Npc_HashNode *p_first, *p_cur, *p_pre;
	bucket_index = hasher1(key, hashpool->_num_bucket);
	p_first = hashpool->_buckets[bucket_index];

	for (p_cur = p_first; p_cur; )
	{ 
		if(p_cur->_key == key)
		{
			if(p_cur == p_first)
			{
				hashpool->_buckets[bucket_index] = p_cur->_next;
			}
			else
			{
				p_pre->_next = p_cur->_next;
			}
			Npc_HashmapFreeNode(hashpool, p_cur);
			return 0;
		}
		p_pre = p_cur;
		p_cur = p_cur->_next;
	}
	return NPC_HASHMAP_NOT_FIND_KEY;/*没有找到*/
}

int Npc_HashmapCount(Npc_HashPool* hashpool)
{
	int count=0, len;
	u_int bucket_index;
	Npc_HashNode *p_first, *p_cur;

	for(bucket_index=0; bucket_index<hashpool->_num_bucket; ++bucket_index)
	{
		len=0;
		p_first = hashpool->_buckets[bucket_index];
		for (p_cur = p_first; p_cur; p_cur = p_cur->_next)
		{ 
			printf("[Hashmap]: [HashmapCount] bucket_index:%d, key=0x%llx, value=%u\n", bucket_index, p_cur->_key, p_cur->_value);
			++count;
			++len;
		}
		if(len>0)
		{
			printf("[Hashmap]: [HashmapCount] bucket index:%d, bucket length:%d\n", bucket_index, len);
		}
	}
	return count;
}
/**************************************************
**
**	清理session_hashmap的函数
**	遍历hash表,如果获取信号量的值出错就删除节点
**	返回值:
**		0
**************************************************/
int Npc_HashmapClear(Npc_HashPool* hashpool)
{
	u_int bucket_index;
	Npc_HashNode *p_first=NULL, *p_cur=NULL, *p_pre=NULL, *p_next=NULL;

	for(bucket_index=0; bucket_index<hashpool->_num_bucket; ++bucket_index)
	{
		p_first = hashpool->_buckets[bucket_index];
		for (p_cur = p_first; p_cur!=NULL; )
		{ 
			if(p_cur->_sem_id>=0 && Dbfw_GetSemValue(p_cur->_sem_id)==-1)
			{
				//if(errno==EIDRM || errno==EINVAL)/*EIDRM值是43. EINVAL(22) */
				//{
#ifdef DEBUG_HASHMAP
					//printf("[Hashmap]: Npc_HashmapClear(): delete key=0x%llx, value=%u, sem_id=%d\n", p_cur->_key, p_cur->_value, p_cur->_sem_id);
#endif
					if(p_cur == p_first)
					{
						hashpool->_buckets[bucket_index] = p_cur->_next;
					}
					else
					{
                        if(p_pre!=NULL)
                        {
                            p_pre->_next = p_cur->_next;
                        }
                        else
                        {
                            /* 之前的全部被清理了,不做任何处理 */
                        }
					}
					p_next = p_cur->_next;
					Npc_HashmapFreeNode(hashpool, p_cur);
					p_cur = p_next;
				//}else
				//{
				//	p_pre = p_cur;
				//	p_cur = p_cur->_next;
				//}
			}
			else
			{
				p_pre = p_cur;
				p_cur = p_cur->_next;
			}

		}
	}
	return 0;
}

void Npc_ConstructNppName(u_char* buf, u_char* instance_name)
{
	static time_t last_time = 0;
	static u_int id = 0;
	time_t cur_time = time(NULL);
	u_int len;
	u_char nppname[32];
	
	if(cur_time != last_time)
	{
		last_time = cur_time;
		id = 0;
	}else
	{
		++id;
	}
	memset(nppname,0,sizeof(nppname));
	strcat((char*)nppname,(char*)buf);
	
	strcpy((char*)buf, "dbfw_");
	strcat((char*)buf, (char*)instance_name);
//	strcat((char*)buf, "_nppc_");
	strcat((char*)buf, "_");
	strcat((char*)buf, (char*)nppname);
	strcat((char*)buf, "c_");

	len = strlen((char*)buf);
	strftime((char*)buf+len, 32, "%Y%m%d%H%M%S", localtime(&cur_time));
	len += 14;
	buf[len]='0'+id/100;
	buf[len+1]='0'+id%100/10;
	buf[len+2]='0'+id%10;
	buf[len+3]='\0';
}

void Npc_Int2Str(u_int n, u_char* buf)
{
	int i=0;
	int val;
	val = n/10000;
	if(val>0)
		buf[i++]=val+'0';
	val = n%10000/1000;
	if(val>0||i>0)
		buf[i++]=val+'0';
	val = n%1000/100;
	if(val>0||i>0)
		buf[i++]=val+'0';
	val = n%100/10;
	if(val>0||i>0)
		buf[i++]=val+'0';
	val = n%10;
	buf[i++]=val+'0';
	buf[i]='\0';

}

void Npc_Sched_CPU()
{
	int num = sysconf(_SC_NPROCESSORS_CONF);
	cpu_set_t mask;

	if(num == 4)
	{
		CPU_ZERO(&mask);
		CPU_SET(0,&mask);
		CPU_SET(1,&mask);
		CPU_SET(2,&mask);
		if (sched_setaffinity(0, sizeof(mask), &mask) == -1)
		{
			printf("warning: could not set CPU affinity\n");
		}
	}	
}

u_short Npc_DynaPortFind(Dbfw_Sga_SessionBuf *sga_session_buf, u_int ip, u_short port)
{
	int i = 0;
	int ret = NPC_HASHMAP_NOT_FIND_KEY;
	for(i = 0;i<sga_session_buf->block_35->ip_count;i++)
	{
		if(sga_session_buf->block_35->dyna_port_ip[i].ip == ip)
		{
			if(sga_session_buf->block_35->dyna_port_ip[i].port_flag[port] == 1)
			{
				ret = 1;
				return ret;
			}
			else
			{
				break;
			}
		}
	}
	return ret;
}


