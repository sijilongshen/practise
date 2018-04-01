CC = gcc
CPP = g++
CFLAGS	= -DUNIX -D_THREAD_SAFE -Iinclude -DHAVE_SELECT
LIBFLAGS = -lpthread -L/usr/lib64/mysql -lmysqlclient -lrt -L./lib ./lib/libpcap.a ./lib/libpfring.a ./lib/libnuma.a

SRCS = nic_stat.cpp

BINOBJS = nic_stat.o 

.SUFFIXES: .exe .o .c .cpp .pc

.PHONY : clean clear
all: nic_stat

nic_stat: $(SRCS) $(BINOBJS)
	$(CPP) -g -o nic_stat $(BINOBJS) $(LIBFLAGS)

nic_stat.o: nic_stat.cpp
	$(CPP) -g -c $(CFLAGS) nic_stat.cpp -o nic_stat.o

clear:
	rm -f *.o

clean:
	rm -rf *.o
	rm -f nic_stat

