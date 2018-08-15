
ifeq ($(strip $(BASEDIR)),)
BASEDIR=../..
endif

ifeq ($(mode),debug)
DEBUG_SWITCH=-g -DDEBUG_SWITCH
endif

source=$(shell ls *.c *.cpp 2>/dev/null )
include=-I$(BASEDIR)/include 
libs   =-L$(BASEDIR)/lib

CC=g++

.PHONY:all clean

target=AClient

all:$(target) 
$(target):$(source)
	$(CC) $(DEBUG_SWITCH) $(GLOBAL_FLAGS) -o $(target) $(include) $(libs) $(source)

install:
	cp -f $(target) $(BASEDIR)/bin

clean:
	-rm -f $(target) *.o

