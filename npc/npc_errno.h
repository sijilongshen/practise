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
#define NPC_ERROR_CAPBUF_OFFSET_NOFIND			-7		/* fixarray��û��capbuf��ƫ���� */
#define NPC_ERROR_ACBUF_OFFSET_NOFIND			-8		/* fixarray��û��acbuf��ƫ���� */
#define NPC_ERROR_INIT_SESSION_HASHMAP			-9
#define NPC_ERROR_INIT_DB_HASHMAP				-10
#define NPC_ERROR_ADDNPPCOUNT_LOCK				-11		/* ����NPP����֮ǰ,����npp������ʱ����ʧ�� */
#define NPC_ERROR_HASHPOOL_ALLUSED				-12		/* hash�����hashpoolû�п��пռ��� */
#define NPC_ERROR_UNLOCKSEM						-13		/* �����ź�����ֵ�ĳ��� */
#define NPC_ERROR_CREATESEM_FOR_CREATENPPTHREAD	-14		/* ��������ͬ�����̺߳ͼ���̵߳��ź���ʧ�� */
#define NPC_ERROR_UNLOCKSEM_FOR_CREATENPPTHREAD	-15		/* ���߳���֪ͨ����̴߳���NPPʱ,�����ź�����ֵʧ�� */
#define NPC_ERROR_INITMUTEX_FOR_CLEARSESSION	-16		/* ��������ͬ�����̺߳�����session_hashmap�̵߳Ļ�����ʧ�� */
#define NPC_ERROR_COMPILE_FILTER				-17		/* ������˹�����ʽ���� */
#define NPC_ERROR_SET_FILTER					-18		/* Ϊ�������ù��˹�����ʽ���� */
#define NPC_ERROR_NOFIND_DBFW_HOME				-19		/* ��fixarray��δ�ҵ�DBFW_HOME */
#define NPC_ERROR_SET_LIBRARY_PATH				-20		/* ����LD_LIBRARY_PATHʧ�� */
#define NPC_ERROR_OPEN_DEVICE					-21		/* ���������� */
#define NPC_ERROR_INVALID_NPCID					-22		/* ��Ч��npc_id����(1-4) */


#endif

