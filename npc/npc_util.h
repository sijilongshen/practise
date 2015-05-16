/********************************************
*
*	npc_util.h
*	工具函数，包括:
*	创建日志
*	IP地址、MAC地址转换
*	Hash表操作
*	构造NPP进程名
*
*********************************************/

#ifndef _NPC_UTIL_H_
#define _NPC_UTIL_H_

#include <stdio.h>
#include <time.h>
#include <string.h>
#include "dbfw_ipc.h"
#include "dbfw_limits.h"
#include "dbfwsga_session.h"

/*****************************************
*	创建一条新日志
*	log_level: 日志级别, e.g. ERROR_LEVEL
*	log: 日志结构体
*	format,... :日志信息
*****************************************/
extern time_t log_time;
#define NPC_NEW_LOG(log_level, log, format, ...)\
{\
    char msg_tmp[1024*10];\
    memset(msg_tmp,0x00,sizeof(msg_tmp));\
    if(log_level==ERROR_LEVEL)\
    {\
	    if(npc_errlog_file.level_enable[log_level]==1)\
	    {\
		    time(&log_time);\
		    strftime((char*)log.cur_time, 32, "%Y-%m-%d %H:%M:%S", localtime(&log_time));\
            sprintf((char*)msg_tmp, format, ## __VA_ARGS__);\
            memcpy((char*)log.msg,msg_tmp,sizeof(log.msg)-1);\
	    }\
    }\
    else\
    {\
        if(npc_log_file.level_enable[log_level]==1)\
        {\
            time(&log_time);\
            strftime((char*)log.cur_time, 32, "%Y-%m-%d %H:%M:%S", localtime(&log_time));\
            sprintf((char*)msg_tmp, format, ## __VA_ARGS__);\
            memcpy((char*)log.msg,msg_tmp,sizeof(log.msg)-1);\
        }\
    }\
}


#ifdef PRINT_INFO
	#define NPC_PRINT(format, ...)\
	{\
		printf(format, ## __VA_ARGS__); \
	}
#else
	#define NPC_PRINT(format, ...)\
	{\
	}
#endif 
/*********************************************
*	
*	将十进制的IP地址转化成字符串
*
*********************************************/
void Npc_Ip2Str(u_int ip, u_char str[]);

/***********************************************
*
*	将6字节的mac地址转化成字符串: AB-CD-EF-01-02-03
*
***********************************************/
void Npc_FormatMacAddress(const u_char *p_mac, u_char mac[]);

/***********************************************
*
*	将6字节的mac地址转化成字符串: ABCDEF010203
*
***********************************************/
void Npc_FormatMacAddress_Clear(const u_char *p_mac, u_char mac[]);

#define NPC_HASHMAP_PRIME_FOR_SESSION         	5987	/*hash函数取模的质数,为 client ip+port => session_id提供 */
#define NPC_HASHMAP_MAX_ELEMENTS_FOR_SESSION  	8320	/*session_hashmp的缓冲池里节点的最大数量, 
														  session最多有8192个,增加了128个冗余节点,
														  因为当session断开时,节点不会被立即回收 
														*/
#define NPC_HASHMAP_PRIME_FOR_DB         		1021	/*hash函数取模的质数,为 db ip+port => 1 提供 */
#define NPC_HASHMAP_MAX_ELEMENTS_FOR_DB  		1024	/*db_hashmap的缓冲池里节点的最大数量，用此值来确定hashpool的大小*/

#define NPC_HASHMAP_NOT_FIND_KEY        65535   /*在hash表中没找到key时返回此值, 给find()和delete()函数使用*/


#pragma pack(1)
/*************************************
**
**	Hashmap中使用的节点
**	22个字节
**************************************/
typedef struct Npc_HashNode
{
    u_int64				_key;			/* 在db_hashmap里,是db ip+port; 在session_hashmap里,是client ip+port */
    u_short				_value;			/* 在db_hashmap里是1; 在session_hashmap里,是session_id(0-8191) */
	int					_sem_id;		/* 在db_hashmap里没有使用;在session_hashmap里,是session_id对应的信号量id */
    struct Npc_HashNode* _next;
}Npc_HashNode;

/**************************************************************
**
**	每个hashmap有一个自己的hashpool
**	db_hashmap占用的大小: 1021*8+1024*22=8168+22528=30696
**	session_hashmap占用的大小: 5987*8+8320*22=47896+183040=230936
**
**************************************************************/
typedef struct Npc_HashPool
{
	void			*_pool;				/*缓冲池首地址的指针*/
	Npc_HashNode	*_header;			/*缓冲池的所有节点构成一个链表,_header用于分配和释放节点*/
	u_int			_size;				/*缓冲池的大小,单位是字节 */
	Npc_HashNode	**_buckets;			/*节点的指针数组*/
	u_int			_num_bucket;		/*桶的数量,是质数*/
	u_int			_num_element;		/*缓冲池最多可容纳的节点数量 */
}Npc_HashPool;

/**************************************************************
**
**	保存所有Session与Client信息的关系
**  数组下标就是session_id
**
**************************************************************/
typedef struct Npc_SessionWithClient
{
    u_int64 client_key;     /* 初始值为0 */
#ifdef USE_BSLHASH_FORSESSION
    u_short session_id;     /* 65535表示该session不存在 */    
#endif
    int     _sem_id;        /* 该session的信号量ID */
    u_int64 timestamp_for_createcpp;    /* 本会话创建NPP的时间戳(用于进行SYN+ACK的检查) */
    u_short dialect;        /* 方言 */
    u_char  is_dynaport;    /* 是否是动态端口 0-否 1-是 */
}Npc_SessionWithClient;

/* 
    2014-10-15 增加保存数据库服务器IP与数据库类型的数据结构 
    为了加快查询的性能，采用IP+PORT产生的key值%64的值为下标的类似“桶”的数据结构
    每个“桶”中又包含DBFW_MAX_PROTECTED_DBADDRESS(1024)个相同hash值的元素
    64:DBFW_MAX_PROTECTED_DATABASE
*/
typedef struct Npc_DBTypeWithIpAndPort_Bucket
{
    u_short dbcount;        /* 桶中包含的数据库实例数量 */
    u_int64 dbserver_key[DBFW_MAX_PROTECTED_DBADDRESS];   /* IP和PORT产生的key值 */
    u_short dialect[DBFW_MAX_PROTECTED_DBADDRESS];        /* 数据库类型(方言),参考dbfw_ac.h中的宏定义 */    
}Npc_DBTypeWithIpAndPort_Bucket;

#pragma pack()

/*********************
**	初始化hashmap
**       返回值
**               0: 成功
**               -1:分配内存失败
**********************/
int Npc_HashmapInit(Npc_HashPool *hashpool);
/************************************************
**
**	将缓冲池清空,重新组织成一个链表
**	将buckets数组清空
**	RETURN
**		0:ok
**		-1:error
************************************************/
int Npc_HashmapReset(Npc_HashPool* hashpool);

/*************************************************
**	向hashmap中插入一个元素
**	若相同key的元素存在，则更新value值
**	系统中信号量id是非负数,这里用-1表示未使用sem_id字段
** 	返回值
**		-1 : 插入了新元素
**		>=0: 更新了已经存在的元素
**       -2 : 分配节点失败,缓冲池用光了
**************************************************/
int Npc_HashmapInsert(Npc_HashPool *hashpool, u_int64 key, u_short value, int sem_id=-1);

/********************************************
**	查找关键字为key的元素
**	返回值
**		>=0: 找到的value
**		NPC_HASHMAP_NOT_FIND_KEY: 没有找到,值是65535
********************************************/
u_short Npc_HashmapFind(Npc_HashPool *hashpool, u_int64 key);

/********************************************
**	删除关键字为key的元素, 把节点放回缓冲池中
**	返回值:       
**		0: 删除成功
**		65535: 没有找到
********************************************/
u_short Npc_HashmapDelete(Npc_HashPool *hashpool, u_int64 key);

/*******************************************
**	计算hashmap中元素的数量
********************************************/
int Npc_HashmapCount(Npc_HashPool *hashpool);

/**************************************************
**
**	清理session_hashmap的函数
**	遍历hash表,如果获取信号量的值出错就删除节点
**	返回值:
**		0
**************************************************/
int Npc_HashmapClear(Npc_HashPool* hashpool);


/*******************************************
**       释放给hashpool分配的内存
*******************************************/
void Npc_HashmapDestroy(Npc_HashPool *hashpool);

/********************************************
*	构造NPP进程名字的函数
*	buf: 将名字存入该缓冲区
*	instance_name: DBFW实例名
********************************************/
void Npc_ConstructNppName(u_char* buf, u_char* instance_name);

void Npc_Int2Str(u_int n, u_char* buf);

/* coredump处理函数 */
void Npc_FaultTrap(int signo, 
					siginfo_t *siginfo, 
					void *context);

void Npc_Sched_CPU();

u_short Npc_DynaPortFind(Dbfw_Sga_SessionBuf *sga_session_buf, u_int ip, u_short port);

#endif

