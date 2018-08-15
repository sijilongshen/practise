
ifeq ($(strip $(BASEDIR)),)
BASEDIR=../..
endif

ifeq ($(mode),debug)
DEBUG_FLAGS=-g -DDEBUG_FLAG
endif

source=$(shell ls *.c *.cpp 2>/dev/null )
include=-I$(BASEDIR)/include 
libs   =-L$(BASEDIR)/lib

CC=g++

.PHONY:all clean

target=AServer

all:$(target) 
$(target):$(source)
	$(CC) $(DEBUG_FLAGS) $(GLOBAL_FLAGS) -o $(target) $(include) $(libs) $(source)

install:
	cp -f $(target) $(BASEDIR)/bin

clean:
	-rm -f $(target) *.o

