#include <stdio.h>
#include "npc_interface.h"
#define HAVE_HEADER_INDEX   /* ����ʹ��header_index���Ұ� */

void Dbfw_InitLoopDataForNPP(CapBuf_LoopData *loop_data, u_char* capbuf_addr, int capbuf_id, u_short session_id)
{
	loop_data->capbuf_addr = capbuf_addr+(capbuf_id-1)*DBFW_CAPBUF_SIZE*2;
	loop_data->header_addr[0] = loop_data->capbuf_addr;
	loop_data->body_addr[0] = loop_data->header_addr[0] + DBFW_CAPBUF_MAX_HEADER_COUNT*DBFW_CAPBUF_HEADER_SIZE;
	loop_data->header_addr[1] = loop_data->header_addr[0] + DBFW_CAPBUF_SIZE;
	loop_data->body_addr[1] = loop_data->header_addr[1] + DBFW_CAPBUF_MAX_HEADER_COUNT*DBFW_CAPBUF_HEADER_SIZE;

	loop_data->buffer_id = 0;
	loop_data->last_header = 0;
	loop_data->next_id = 1;
	loop_data->session_id = session_id;
}


CapBuf_Header* Dbfw_GetNewHeaderForNPP(CapBuf_LoopData *loop_data)
{
	CapBuf_Header *new_header; 
	u_char *p_header = NULL;
    u_char *p_header_foridx = NULL;
	int i;
    int tmp_session_id = 0;
    int next_header_idx = 0;
    u_char tmp_bufferid = 0;
	int max_find_count=(DBFW_CAPBUF_MAX_HEADER_COUNT<<1);/*���������黺�����е�����header*/
//#ifdef DEBUG
//	CapBuf_Header *last_header;
//#endif
	//p_header = ( (loop_data->last_header==(u_char*)0)?loop_data->header_addr[loop_data->buffer_id]:(loop_data->last_header+DBFW_CAPBUF_HEADER_SIZE) );
    if(loop_data->last_header==(u_char*)0)
    {
        /* ��һ�� */
        //printf("loop_data->last_header==(u_char*)0\n");
        p_header = loop_data->header_addr[loop_data->buffer_id];
        next_header_idx = DBFW_NEXTHEADERIDX_UNKNOWN;
    }
    else
    {
        p_header = (u_char*)loop_data->last_header+DBFW_CAPBUF_HEADER_SIZE;
        /* ȡ�õ�ǰheader���趨��next_header_idx */
        if(((CapBuf_Header*)(loop_data->last_header))->session_id==loop_data->session_id||
           ((CapBuf_Header*)(loop_data->last_header))->session_id==65535
          )
        {
            /* ֮ǰ�ĻỰ��λû�б������Ựռ�� */
            next_header_idx = ((CapBuf_Header*)(loop_data->last_header))->next_header_idx;
        }
        else
        {
            next_header_idx = DBFW_NEXTHEADERIDX_UNKNOWN;
        }
        //printf("loop_data->last_header->next_header_idx=%d\n",((CapBuf_Header*)(loop_data->last_header))->next_header_idx);
    }
	/* �ȳ��Ը���next_header_idx�ҵ���һ����λ */
#ifdef HAVE_HEADER_INDEX
    if(next_header_idx!=DBFW_NEXTHEADERIDX_UNKNOWN)
    {
        if(next_header_idx<DBFW_CAPBUF_MAX_HEADER_COUNT)
        {
            /* �ǵ�һ��buffer�� */
            p_header_foridx = loop_data->header_addr[0];
            p_header_foridx += next_header_idx*DBFW_CAPBUF_HEADER_SIZE;
            tmp_bufferid = 0;
        }
        else
        {
            /* �ǵڶ����� */
            p_header_foridx = loop_data->header_addr[1];
            p_header_foridx += (next_header_idx-DBFW_CAPBUF_MAX_HEADER_COUNT)*DBFW_CAPBUF_HEADER_SIZE;
            tmp_bufferid = 1;
        }
        if(((CapBuf_Header*)p_header_foridx)->session_id==(u_int)(loop_data->session_id) &&
           ((CapBuf_Header*)p_header_foridx)->id>=loop_data->next_id
          )
        {
            /* �ҵ��˶�Ӧ�Ĳ�λ������֤������ȷ */
            //printf("Find new_header with next_header_idx=%d\n",next_header_idx);
            new_header=(CapBuf_Header*)p_header_foridx;
            loop_data->next_id=new_header->id+1;
            loop_data->last_header = (u_char*)new_header;
            loop_data->buffer_id = tmp_bufferid;
            __sync_lock_test_and_set(&(new_header->session_id), 65535);
            return new_header;   
        }
    }
#endif
    /* ��������û���ҵ�����ʹ�ñ����ķ�ʽ���� */
    //printf("**************************LOOP MODE******************************\n");
	for(i=0;i<max_find_count;++i)
	{
		/*�л�����һ��buffer*/
		if(p_header>=loop_data->body_addr[loop_data->buffer_id])
		{
#ifdef DEBUG_NPPDEMO
			printf("[Npp Info]:****************switch capbuf*************\n");
			printf("\tp_header:%lu, body_addr[%u]:%lu\n",
						p_header-loop_data->header_addr[0],
						loop_data->buffer_id,
						loop_data->body_addr[loop_data->buffer_id]-loop_data->header_addr[0]);
			//last_header = (CapBuf_Header*)(p_header-DBFW_CAPBUF_HEADER_SIZE);
			printf("\tcur_header: session_id:%u, id:%llu, data_offset:%u, data_size:%u\n",
						((CapBuf_Header*)loop_data->last_header)->session_id,
						((CapBuf_Header*)loop_data->last_header)->id,
						((CapBuf_Header*)loop_data->last_header)->data_offset,
						((CapBuf_Header*)loop_data->last_header)->data_size);

#endif
			//printf("[switch capbuf]: %d\n",1-loop_data->buffer_id);
			loop_data->buffer_id = 1-loop_data->buffer_id;
			p_header = loop_data->header_addr[loop_data->buffer_id];
#ifdef DEBUG_NPPDEMO
			printf("[switch capbuf]: next_header: session_id:%u, id:%llu, data_offset:%u, data_size:%u\n",
						new_header->session_id,
						new_header->id,
						new_header->data_offset,
						new_header->data_size);
#endif
		}
		/*�жϵ�ǰheader�����ڱ�session��header*/
		new_header=(CapBuf_Header*)p_header;
		//printf("[finding]: session_id:%u, id:%llu, data_offset:%u, data_size:%u\n",
		//				new_header->session_id,
		//				new_header->id,
		//				new_header->data_offset,
		//				new_header->data_size);
        //tmp_session_id = Dbfw_FetchAndAdd(&(new_header->session_id),0); /* 2014-06-23 ��Ϊʹ��ԭ�Ӳ������ȡ��ȷ��sessionid������������ݲ���ȷ */
        tmp_session_id = new_header->session_id; /* ��ȡsessionid */
		//if(new_header->session_id==(u_int)(loop_data->session_id) &&
        if(tmp_session_id==(u_int)(loop_data->session_id) &&
			//new_header->id==loop_data->next_id) /* TODO:����߼����ڴ����������capbuf�е����ݰ���ѭ��д���ǵ����󣬻����һֱ�޷�����new_header->id==loop_data->next_id����������ѭ������,��ȷ��Ӧ����new_header->id>=loop_data->next_id,���ҽ�loop_data->next_id=new_header->id+1 */
            new_header->id>=loop_data->next_id)
		{
			//++loop_data->next_id; /* ��Ϊloop_data->next_id=new_header->id+1 */
            loop_data->next_id=new_header->id+1;
			loop_data->last_header = (u_char*)new_header;
			__sync_lock_test_and_set(&(new_header->session_id), 65535);
			//new_header->session_id = 65535;
			//printf("[find]: session_id:%u, id:%llu, data_offset:%u, data_size:%u\n",
			//			new_header->session_id,
			//			new_header->id,
			//			new_header->data_offset,
			//			new_header->data_size);
            //printf("i=%d\n",i);
            //printf("**************************i=%d******************************\n",i);
			return new_header;   
		}

		p_header += DBFW_CAPBUF_HEADER_SIZE;        	          
	}    
	return NULL;
}

