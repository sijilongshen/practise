#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "pcap.h"

typedef struct Nic_Info{
    pcap_t *pcap_handle;
    int datalink;
	char nic_name[64];
	long long cap_pkg_num;
	long long tcp_num;
	long long udp_num;
    bool enable;
}nic_info;

#define SNAP_LEN 65536
#define CAP_READ_TIMEOUT            200

nic_info Nic_Mgr[16];
char errbuf[PCAP_ERRBUF_SIZE];
unsigned char* packet_buffer = NULL;
static char filter[1024] = {0};
static int use_filter = 0;
static char use_dev[64];
////////////////////////////////////////////////
int find_all_dev();
int open_all_dev();
static void capture_packet_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content);
void process_packet(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);
int close_all_dev();

void usage()
{
    return ;
}

int main(int argc, char* argv[])
{
	int ret = 0;
    int index = 0;
    int opt, list_dev;

	while((opt=getopt(argc, argv, "lf:i:"))!=-1)
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
			default:
				usage();
				return 0;
		}
	}	

	memset(Nic_Mgr, 0x00, sizeof(nic_info) * 16 );
    packet_buffer = (unsigned char*)malloc(64*1024);
    if ( packet_buffer == NULL)
    {
        printf("malloc mem failed\n");
        return 0;
    }
    if ( list_dev == 1)
    {
        //  找到所有的网卡并存储
        find_all_dev();
        exit(0);
    }

    find_all_dev();
	//  打开网卡设备 
	open_all_dev();
	//  开始抓包
    while (1)
    {
        if ( Nic_Mgr[index].pcap_handle != NULL)
        {
            pcap_dispatch(Nic_Mgr[index].pcap_handle, -1, capture_packet_callback, (u_char*)&index);
            //pcap_dispatch(Nic_Mgr[index].pcap_handle, -1, process_packet, NULL);
        }else{
            printf("no pcap_handle can be used\n");
            break;
        }
    }
    // pcap_loop(Nic_Mgr[0].pcap_handle, -1, capture_packet_callback, NULL);

    close_all_dev();
	return 0;
}

static int Rma_ParseSourceAndDestIpPort(u_char *p_frame_packet,
        u_int* src_ip, u_short *src_port,u_int* dst_ip, u_short *dst_port)
{
    u_char* p_ip_packet;
    u_char* p_tcp_packet;
    u_int ip_header_len;
    u_int cursor = 0;

    cursor = cursor + 14;
    p_ip_packet = p_frame_packet+cursor;

    /*解析出源ip*/
    *src_ip = ntohl(*(u_int*)(p_ip_packet+12));
    /*解析出目的ip*/
    *dst_ip = ntohl(*(u_int*)(p_ip_packet+16));

    ip_header_len = (*p_ip_packet)&0x0f;
    p_tcp_packet = p_ip_packet + (ip_header_len<<2);
    /*解析出源port*/
    *src_port = ntohs(*(u_short*)p_tcp_packet);
    /*解析出目的port*/
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
    int parse_ret = 0;
    
    if ( Nic_Mgr[index].datalink == DLT_LINUX_SLL )
    {
        memcpy(packet_buffer, packet_content + 2, packet_header->caplen - 2);
        packet_current = packet_buffer;
    }else{
        memcpy(packet_buffer, packet_content, packet_header->caplen );
        packet_current = packet_buffer;
    }

    parse_ret = Rma_ParseSourceAndDestIpPort(packet_current, &src_ip, &src_port, &dst_ip, &dst_port);
    if (parse_ret < 0)
    {
        printf("capture_packet_callback parse failed, no matched packet,ret:%d\n",parse_ret);
        return;
    }
    else
    {
        nic_Ip2Str(src_ip, (u_char*)str_src_ip);
        nic_Ip2Str(dst_ip, (u_char*)str_dst_ip);
        printf("from_ip:%s,from_port=%u,to_ip=%s,to_port=%u\n", str_src_ip, src_port, str_dst_ip, dst_port);
    }

    return;

}

int open_all_dev()
{
    int index = 0;
    int promisc = 1;
    struct bpf_program bpf_filter;

    Nic_Mgr[index].pcap_handle = pcap_open_live((const char*)Nic_Mgr[index].nic_name, SNAP_LEN, promisc, CAP_READ_TIMEOUT,errbuf); 
    if ( Nic_Mgr[index].pcap_handle == NULL )
    {
        printf("open device %s failed , error buf %s \n", Nic_Mgr[index].nic_name, errbuf);
        return -1;
    }else{
        printf("open device %s success \n", Nic_Mgr[index].nic_name);
        Nic_Mgr[index].datalink = pcap_datalink(Nic_Mgr[index].pcap_handle);
        if ( use_filter == 1 )
        {
            printf("use filter %s \n", filter);
            if(pcap_compile(Nic_Mgr[index].pcap_handle,&bpf_filter,(const char*)filter,1,0xFFFFFF00) == -1)
            {
                printf("compile filter failed\n");
                exit(1);
            }
            if(pcap_setfilter(Nic_Mgr[index].pcap_handle,&bpf_filter) == -1)
            {
                printf("setfilter failed \n");
                return -1;
            }
        }
    }

    return index;
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
