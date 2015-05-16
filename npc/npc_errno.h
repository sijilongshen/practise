/********************************************************************
**	npc_errno.h
**
**	purpose: 
**		error number of npc process
** 
**	author:  madianjun@schina.cn
**	Copyright (C) 2012 SChina (www.schina.cn) 
**	
*********************************************************************/
#ifndef _NPC_ERRNO_H_
#define _NPC_ERRNO_H_
#include "dbfw_global.h"

#define NPC_ERRNO_START							41000

#define NPC_ERROR_DEVICENAME_NULL				-1
#define NPC_ERROR_SHMID_NULL					-2
#define NPC_ERROR_DBFWLOGHOME_NULL				-3
#define NPC_ERROR_DBFWINSTNAME_NULL				-4
#define NPC_ERROR_NPCLOGDIRECTORY_NOEXIST		-5
#define NPC_ERROR_ATTACHSHM						-6
#define NPC_ERROR_CAPBUF_OFFSET_NOFIND			-7		/* fixarray里没有capbuf的偏移量 */
#define NPC_ERROR_ACBUF_OFFSET_NOFIND			-8		/* fixarray里没有acbuf的偏移量 */
#define NPC_ERROR_INIT_SESSION_HASHMAP			-9
#define NPC_ERROR_INIT_DB_HASHMAP				-10
#define NPC_ERROR_ADDNPPCOUNT_LOCK				-11		/* 创建NPP进程之前,增加npp计数器时加锁失败 */
#define NPC_ERROR_HASHPOOL_ALLUSED				-12		/* hash缓冲池hashpool没有空闲空间了 */
#define NPC_ERROR_UNLOCKSEM						-13		/* 增加信号量的值的出错 */
#define NPC_ERROR_CREATESEM_FOR_CREATENPPTHREAD	-14		/* 创建用于同步主线程和监测线程的信号量失败 */
#define NPC_ERROR_UNLOCKSEM_FOR_CREATENPPTHREAD	-15		/* 主线程在通知监测线程创建NPP时,增加信号量的值失败 */
#define NPC_ERROR_INITMUTEX_FOR_CLEARSESSION	-16		/* 创建用于同步主线程和清理session_hashmap线程的互斥量失败 */
#define NPC_ERROR_COMPILE_FILTER				-17		/* 编译过滤规则表达式出错 */
#define NPC_ERROR_SET_FILTER					-18		/* 为网卡设置过滤规则表达式出错 */
#define NPC_ERROR_NOFIND_DBFW_HOME				-19		/* 在fixarray中未找到DBFW_HOME */
#define NPC_ERROR_SET_LIBRARY_PATH				-20		/* 设置LD_LIBRARY_PATH失败 */
#define NPC_ERROR_OPEN_DEVICE					-21		/* 打开网卡出错 */
#define NPC_ERROR_INVALID_NPCID					-22		/* 无效的npc_id参数(1-4) */


#endif

