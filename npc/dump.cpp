#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "dump.h"


uint16_t in_cksum(void *data, int len, uint32_t *ret_sum) {
    uint32_t    sum    = 0;
    int         i      = len >> 1,
                endian = 1; // big endian
    uint16_t    crc,
                *p     = (uint16_t *)data;

    if(*(char *)&endian) endian = 0;
    if(ret_sum) sum = *ret_sum;
    while(i--) sum += *p++;
    if(len & 1) sum += *p & (endian ? 0xff00 : 0xff);
    if(ret_sum) *ret_sum = sum;
    crc = sum = (sum >> 16) + (sum & 0xffff);
    if(sum >>= 16) crc += sum;
    if(!endian) crc = (crc >> 8) | (crc << 8);
    return(~crc);
}

uint16_t net16(uint16_t num) {
    int         endian = 1; // big endian

    if(!*(char *)&endian) return(num);
    return((num << 8) | (num >> 8));
}



uint32_t net32(uint32_t num) {
    int         endian = 1; // big endian

    if(!*(char *)&endian) return(num);
    return(((num & 0xff000000) >> 24) |
           ((num & 0x00ff0000) >>  8) |
           ((num & 0x0000ff00) <<  8) |
           ((num & 0x000000ff) << 24));
}


void putxx(FILE *fd, uint32_t num, int bits) {
    int         i,
                bytes;

    bytes = bits >> 3;
    for(i = 0; i < bytes; i++) {
        fputc(num >> (i << 3), fd);
    }
}

void create_acp(FILE *fd) {
    if(!fd) return;
    putxx(fd, 0xa1b2c3d4, 32);
    putxx(fd, 2,          16);
    putxx(fd, 4,          16);
    putxx(fd, 0,          32);
    putxx(fd, 0,          32);
    putxx(fd, 65535,      32);
    putxx(fd, 1,          32);
    fflush(fd);
}

struct timevalx
{
	uint32_t	tv_sec;
	uint32_t	tv_usec;
};


void acp_dump(FILE *fd, uint8_t *data, int len)
{

    struct {
        struct timevalx ts;
        uint32_t        caplen;
        uint32_t        len;
    } acp_pck;

	struct timeval cur_time;

    if(!fd) return;
  
    // use the following if gettimeofday doesn't exist on Windows
     //acp_pck.ts.tv_sec  = time(NULL);
     //acp_pck.ts.tv_usec = GetTickCount();
    gettimeofday((struct timeval *)&(cur_time), NULL);

	acp_pck.ts.tv_sec	= cur_time.tv_sec;
	acp_pck.ts.tv_usec	= cur_time.tv_usec;
	acp_pck.caplen		= len;
	acp_pck.len			= len;

    // SOCK_RAW
	fwrite(&acp_pck,  sizeof(acp_pck), 1, fd);
	fwrite(data,      len,             1, fd);
	fflush(fd);
	return;

}


void Npc_Dump(FILE *fd, uint8_t *data, int len)
{
	//SOCK_STREAM, IPPROTO_TCP
	acp_dump(fd, data, len);
}
