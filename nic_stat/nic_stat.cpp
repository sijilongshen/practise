#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include "mysql/mysql.h"

#include "pcap.h"

typedef struct Nic_Info{
    pcap_t *pcap_handle;
    int datalink;
	char nic_name[64];
	long int cap_byte_num;
    long int cap_byte_per;
	long int cap_pkg_num;
	long int tcp_num;
	long int udp_num;
    int death_of_ping_flag;
    int land_flag;
    bool enable;
}nic_info;

#define SNAP_LEN 65536
#define CAP_READ_TIMEOUT            200

nic_info Nic_Mgr[16];
char errbuf[PCAP_ERRBUF_SIZE];
unsigned char* packet_buffer = NULL;
int INDEX=0;
static char filter[1024] = {0};
static int use_filter = 0;
static int show_traffic = 0;
static int defense_mode = 0;
static char use_dev[64];
pthread_mutex_t data_access_mutex = PTHREAD_MUTEX_INITIALIZER;
////////////////////////////////////////////////
int find_all_dev();
int open_all_dev();
static void capture_packet_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content);
void process_packet(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);
int close_all_dev();
void* thread_sync_mysql(void* arg);

void usage()
{
    printf("nic_stat: capture packets from nic eth1\n");
    printf("\t-l : show available nic\n");
    printf("\t-i : capture from nic\n");
    printf("\t\teg:-i eth1 \n");
    printf("\t-f : capture use filter \n");
    printf("\t\teg:'tcp' or 'udp' or 'dst port 22' or 'src 192.168.31.130'\n");
    printf("\t-v : show tips \n");
    printf("\t-s : show traffic\n");
    return ;
}

int main(int argc, char* argv[])
{
	int ret = 0;
    int index = 0;
    int opt, list_dev;
    pthread_t    id_thread;

	while((opt=getopt(argc, argv, "lsdvf:i:"))!=-1)
	{
		switch(opt)
		{
			case 'f':
                memset(filter, 0x00, sizeof(filter));
				strncpy(filter, optarg, sizeof(filter)-1);
                use_filter = 1;
				break;
			case 'i':
                memset(use_dev, 0x00, sizeof(use_dev));
				strncpy(use_dev, optarg, sizeof(use_dev)-1);
				break;
			case 'l':
                list_dev = 1;
				break;
			case 's':
                show_traffic = 1;
				break;
			case 'd':
                defense_mode = 1;
				break;
			default:
				usage();
				return 0;
		}
	}	
    if ( argc == 1 )
    {
        usage();
		return 0;
    }

	memset(Nic_Mgr, 0x00, sizeof(nic_info) * 16 );
    //packet_buffer = (unsigned char*)malloc(64*1024);
    //if ( packet_buffer == NULL)
    //{
    //    printf("malloc mem failed\n");
    //    return 0;
    //}
    if ( list_dev == 1)
    {
        //  �ҵ����е��������洢
        find_all_dev();
        exit(0);
    }

    find_all_dev();
	//  �������豸 
	open_all_dev();
	
    if ( pthread_create( &id_thread, NULL, thread_sync_mysql, NULL) )
    {
        printf("create thread failed\n");
        exit(1);
    }
        
    //  ��ʼץ��
    while (1)
    {
        if ( Nic_Mgr[INDEX].pcap_handle != NULL)
        {
            pcap_dispatch(Nic_Mgr[INDEX].pcap_handle, -1, capture_packet_callback, (u_char*)&INDEX);
        }else{
            printf("no pcap_handle can be used\n");
            break;
        }
    }

    close_all_dev();
	return 0;
}

static int parse_protocol(const u_char *p_frame_packet, int* proto, int* syn_flag)
{
	const u_char* p_ip_packet;
	const u_char* p_tcp_packet;
	u_int ip_header_len;
    u_int cursor = 0;
	u_char protocol;
	u_char control_field;
    u_short eth_type_code = 0;

    memcpy(&eth_type_code,(u_char*)p_frame_packet+12,sizeof(u_short));
    eth_type_code = ntohs(eth_type_code);
    cursor = 14;
    p_ip_packet = p_frame_packet+cursor;    
    while(eth_type_code==0x8100)
    {
        /* 
            Type: 802.1Q Virtual LAN (0x8100),�������2�ֽڵ�VLan��Ϣ��2�ֽڵ�type��Ϣ 
            �������type��Ϣ����0x8000
        */
        cursor = cursor + 2;
        memcpy(&eth_type_code,(u_char*)p_frame_packet+cursor,sizeof(u_short));
        eth_type_code = ntohs(eth_type_code);
        cursor = cursor + 2;
        p_ip_packet = p_frame_packet+cursor;

        if(cursor>(14+20))
        {
            *proto = 0;
            *syn_flag = 0;
            return -1;
        }
    }

	protocol = *(p_ip_packet+9);
	if(protocol == 0x06)
	{
		*proto = 1;
	}else if( protocol == 0x11 )
    {
        *proto = 2;
    }else{
        *proto = 0;
    }
	
    ip_header_len = (*p_ip_packet)&0x0f;
	p_tcp_packet = p_ip_packet + (ip_header_len<<2);
    
	control_field = *(p_tcp_packet+13);
    if((control_field&0x12)==0x02)
    {
        // SYN
        *syn_flag = 1;
    }
    else if((control_field&0x12)==0x12)
    {
        // SYN + ACK
        *syn_flag = 2;
    }else{
        *syn_flag = 0;
    }

	return 0;
}

static int parse_ip_port(const u_char *p_frame_packet, u_int* src_ip, u_short *src_port, u_int* dst_ip, u_short *dst_port)
{
    int ret = 0;
    const u_char* p_ip_packet;
    const u_char* p_ip;
    const u_char* p_tcp_packet;
    u_int ip_header_len;
    u_int cursor = 0;

    cursor = cursor + 14;
    p_ip_packet = p_frame_packet+cursor;

    /*������Դip*/
    *src_ip = ntohl(*(u_int*)(p_ip_packet+12));
    /*������Ŀ��ip*/
    *dst_ip = ntohl(*(u_int*)(p_ip_packet+16));

    ip_header_len = (*p_ip_packet)&0x0f;
    p_tcp_packet = p_ip_packet + (ip_header_len<<2);
    /*������Դport*/
    *src_port = ntohs(*(u_short*)p_tcp_packet);
    /*������Ŀ��port*/
    *dst_port = ntohs(*(u_short*)(p_tcp_packet+2));

    return 0;
}

void process_packet(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    int i=0;
    unsigned long counter=0;

    printf("Packet Count:%d\n", ++counter);
    printf("Received Packer Size:%d\n", pkthdr->len);
    printf("Payload:\n");
    for (i=0;i<pkthdr->len;i++)
    {
        if (isprint(packet[i]))
            printf("%c ", packet[i]);
        else
            printf(". ");
        if ((i%16 == 0 && i != 0) || i == pkthdr->len-1 )
            printf("\n");
    }
    return;
}

void nic_Ip2Str(unsigned int ip, unsigned char str[])
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

static void capture_packet_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content)
{
    u_char* packet_current = NULL;
    u_int src_ip, dst_ip;
    u_short src_port, dst_port;
    u_char str_src_ip[128]={0};
    u_char str_dst_ip[128]={0};
    int index = (int)*argument;
    int proto = 0;
    int syn_flag = 0;
    int parse_ret = 0;

    pthread_mutex_lock(&data_access_mutex);
    Nic_Mgr[index].cap_pkg_num ++;
    Nic_Mgr[index].cap_byte_num += packet_header->caplen;
    Nic_Mgr[index].cap_byte_per += packet_header->caplen; 
    pthread_mutex_unlock(&data_access_mutex);

    if ( Nic_Mgr[index].datalink == DLT_LINUX_SLL )
    {
        packet_current = packet_buffer +2;
    }else{
        packet_current = packet_buffer;
    }

    if (parse_protocol(packet_current, &proto, &syn_flag) == -1)
    {
        return;
    }else{
        if ( proto == 1 )
            Nic_Mgr[index].tcp_num ++;
        else if ( proto == 2 )
            Nic_Mgr[index].udp_num ++;
    }

    if ( defense_mode == 1 )
    {
        // ����ģʽ ���� land  �� death of ping �������������ʾ
        parse_ret = parse_ip_port(packet_current, &src_ip, &src_port, &dst_ip, &dst_port);
        if (parse_ret < 0)
        {
            //printf("capture_packet_callback parse failed, no matched packet,ret:%d\n",parse_ret);
            return;
        }
        else
        {
            if ( src_ip == dst_ip )
            {
                printf("capture_packet_callback find death_of_ping packet\n\n");
                nic_Ip2Str(src_ip, (u_char*)str_src_ip);
                nic_Ip2Str(dst_ip, (u_char*)str_dst_ip);
                printf("from_ip:%s,from_port=%u,to_ip=%s,to_port=%u\n", str_src_ip, src_port, str_dst_ip, dst_port);
            }
        }
    }
    return;
}

void* thread_sync_mysql(void* arg)
{
    MYSQL *connection = NULL;
    char sql[1024] = {0};
    bool my_true = 1;
    
    if( (connection = mysql_init(NULL)) == NULL || mysql_options(connection, MYSQL_OPT_RECONNECT, &my_true) || mysql_options(connection, MYSQL_SET_CHARSET_NAME, "utf-8") ||
        mysql_real_connect(connection, "127.0.0.1", "root", "1", "nic_stat", 3306, NULL, 0) == NULL)
    {
        connection = NULL;
        printf("connect_to_dataserver failed\n");
        exit(1);
    }
    
    //  ͬ�����ݵ�mysql���ݿ���
    while (1)
    {
        sleep(1);
        memset(sql, 0x00, sizeof(sql));
        pthread_mutex_lock(&data_access_mutex);
        sprintf(sql, "insert into packet_detail (nic_name,rxpck_total,speed_byte_per,logtime,death_of_ping_flag,land_flag) values\
                ('%s',%ld,%ld,SYSDATE(),%d,%d)", Nic_Mgr[INDEX].nic_name, Nic_Mgr[INDEX].cap_byte_num, Nic_Mgr[INDEX].cap_byte_per, \
                Nic_Mgr[INDEX].death_of_ping_flag, Nic_Mgr[INDEX].land_flag);
        if( mysql_query(connection, sql) != 0)
		{
			printf("exec sql failed \n");
            exit(1);
		}
        Nic_Mgr[INDEX].cap_byte_per = 0;
        pthread_mutex_unlock(&data_access_mutex);
    }
    
}

int open_all_dev()
{
    //int index = 0;
    int promisc = 1;
    struct bpf_program bpf_filter;

    Nic_Mgr[INDEX].pcap_handle = pcap_open_live((const char*)Nic_Mgr[INDEX].nic_name, SNAP_LEN, promisc, CAP_READ_TIMEOUT,errbuf); 
    if ( Nic_Mgr[INDEX].pcap_handle == NULL )
    {
        printf("open device %s failed , error buf %s \n", Nic_Mgr[INDEX].nic_name, errbuf);
        return -1;
    }else{
        printf("open device %s success \n", Nic_Mgr[INDEX].nic_name);
        Nic_Mgr[INDEX].datalink = pcap_datalink(Nic_Mgr[INDEX].pcap_handle);
        if ( use_filter == 1 )
        {
            printf("use filter %s \n", filter);
            if(pcap_compile(Nic_Mgr[INDEX].pcap_handle,&bpf_filter,(const char*)filter,1,0xFFFFFF00) == -1)
            {
                printf("compile filter failed\n");
                exit(1);
            }
            if(pcap_setfilter(Nic_Mgr[INDEX].pcap_handle,&bpf_filter) == -1)
            {
                printf("setfilter failed \n");
                return -1;
            }
        }
    }

    return INDEX;
}

int close_all_dev()
{
    int index = 0;

    for (index=0; index < 16;index ++)
    {
        if ( Nic_Mgr[index].pcap_handle != NULL)
        {
            pcap_close(Nic_Mgr[index].pcap_handle);
        }
    }

    return index;
}

int find_all_dev()
{
	pcap_if_t *alldev, *dev;
    pcap_addr_t *addr;
	int index = 0;

    if ( strlen(use_dev) != 0)
    {
        strncpy(Nic_Mgr[0].nic_name, use_dev, sizeof(Nic_Mgr[0].nic_name)-1);
        Nic_Mgr[0].enable = 1;
    }else{
        if(pcap_findalldevs(&alldev,errbuf)==-1)  
        {  
            printf("find all devices is error\n");  
            return -1;
        } 

        for (dev=alldev; dev != NULL; dev = dev->next)
        {
            //printf("get nic_name = %s\n", dev->name);
            for ( addr=dev->addresses; addr != NULL; addr = addr->next )
            {
                if ( addr->addr && addr->addr->sa_family != AF_INET)
                {
                    continue;
                }else{
                    strncpy(Nic_Mgr[index].nic_name, dev->name, strlen(dev->name));
                    printf("get nic_name = %s\n", Nic_Mgr[index].nic_name);
                    if (addr->addr != NULL)
                    {
                        Nic_Mgr[index].enable = 1;
                    }
                    index ++;
                }
            }
        }
    }
	return index;
}
