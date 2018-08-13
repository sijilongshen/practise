source=$(shell ls *.c *.cpp 2>/dev/null )
include=-I$(BASEDIR)/depend/include 
libs   =-L$(BASEDIR)/depend/lib

CC=g++

.PHONY:all clean

target=AClient

all:$(target) 
$(target):$(source)
	$(CC) -o $(target) $(include) $(libs) $(source)

install:
	cp -f $(target) $(BASEDIR)/bin

clean:
	-rm -f $(target) *.o

