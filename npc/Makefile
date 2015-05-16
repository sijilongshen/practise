include ${DBFW_HOME}/xsecure_dbfw_env.mk
BASEDIR= $(DBFW_HOME)

#NPC_DEFINE+= -DCK_LICENCE_TIME -DCK_LICENCE_TIME_YEAR=2014 -DCK_LICENCE_TIME_MON=7 -DCK_LICENCE_TIME_DAY=31
#NPC_DEFINE+= -DNO_LICENCE
NPC_DEFINE+= -DDBFW_VERSION_MAX_PREDEF=$(DBFW_VERSION_MAX)
NPC_DEFINE+= -DDBFW_VERSION_MIN_PREDEF=$(DBFW_VERSION_MIN)
NPC_DEFINE+= -DDBFW_VERSION_PATCH_PREDEF=$(DBFW_VERSION_PATCH)
NPC_DEFINE+= -DBUILD_DATE_PREDEF=$(BUILD_DATE)
NPC_DEFINE+= -DBUILD_SVN_PREDEF=$(BUILD_SVN)

NPC_DEFINE+= -DHAVE_LIBTIS
#NPC_DEFINE+= -DDEBUG_HASHMAP
#NPC_DEFINE+= -DPRINT_INFO
#NPC_DEFINE+= -DDUMP_PACKET
#NPC_DEFINE+= -DPRINT_STATS #print drop packets count
#NPC_DEFINE+= -DDROP_STABLE_STEP=20 -DDROP_STABLE_INDEX=3
#NPC_DEFINE+= -DDROP_RANDOM=10
NPC_DEFINE+= -DUSE_FILTER  #use filter expression in fixarray
#NPC_DEFINE += -DPRINT_THROUGHPUT
#NPC_DEFINE+= -DTEST_NPC_CAPTUER
NPC_DEFINE+= -DHAVE_PF_RING
# 2014-04-05 增加无连接会话审计支持(最早应用于天津市胸科医院)
NPC_DEFINE+= -DHAVE_NOCONNECT_SESSION
# 2014-10-16 增加NPP进程分离支持
NPC_DEFINE+= -DHAVE_SPLIT_NPP
# 2015-05-07 增加hash表方式的session和client管理
NPC_DEFINE += -DUSE_BSLHASH_FORSESSION

INCLUDE=-I$(BASEDIR)/include \
        -I$(BASEDIR)/depend/include/glib/glib-2.0\
        -I$(BASEDIR)/depend/lib/glib/glib-2.0/include \
        -I$(BASEDIR)/depend/include/libpcap \
        -I. \
        -I$(BASEDIR)/src/npp

MYCOMPILE.cc=g++
MYCOMPILE.c=g++

#MYCOMPILE.cc+= $(DCFLAGS) $(NPC_DEFINE) -D_MAXPROTECTEDDATABASE=64 $(INCLUDE)
MYCOMPILE.cc+= $(NPC_DEFINE) -D_MAXPROTECTEDDATABASE=64 $(INCLUDE)

#MYCOMPILE.c+= $(DCFLAGS) $(NPC_DEFINE) -D_MAXPROTECTEDDATABASE=64  $(INCLUDE)
MYCOMPILE.c+= $(NPC_DEFINE) -D_MAXPROTECTEDDATABASE=64  $(INCLUDE)

TARGET = npc

LIB= -L$(BASEDIR)/lib \
	-L$(BASEDIR)/depend/lib/glib \
	-L$(BASEDIR)/depend/lib/pcre \
	-L. \
	-ldbfw_ac \
	-lsessbuf 	\
	-ldbfw_sql_rewrites \
        -ldbfw_sql_parsers \
	-ldbfw_sql_replaces \
	-ldbfw_vpatch	\
	-lrisk_engine	\
	-lsecureService \
	-lpcre_s	\
	-ldbfw_log      \
        -lfixarray      \
  -ltis \
-lpfring \
-lpcap \
	-lglib-2.0 \
        -lpthread \
	-rdynamic \
	-ldbfw_cklicense \
	 -ldspr


BIN= $(BASEDIR)/bin

SOURCES =  capture-pcap-util.c	\
	capture_ifinfo.c	\
	capture_opts.c	\
	capture_sync.c	\
	pcapio.c	\
	capture-pcap-util-unix.c 

OBJECTS = $(SOURCES:.c=.o)

NPC = npc

TARGET =  $(NPC) 
SETNPC = setnpc.sh

all:  $(TARGET) libcapbuf.a

$(NPC): $(OBJECTS) npc.o npc_util.o dump.o
	$(LD) $(LFLAGS) -o $@ $^ $(LIB) -Wl,-rpath=/home/dbfw/dbfw/lib:../lib:$(BASEDIR)/lib:$(BASEDIR)

libcapbuf.a: npc_interface.o
	ar -r $@ $^
	cp -f libcapbuf.a $(BASEDIR)/lib

%.o: %.c
	$(MYCOMPILE.c) -c $<

%.o: %.cpp
	$(MYCOMPILE.cc) -c $<

clear:  
	rm -f *.o
	rm -f *.a

clean:  clear
	rm -f $(TARGET)

install:
	cp -r $(NPC) $(BASEDIR)/bin
	cp -r $(SETNPC) $(BASEDIR)/bin



