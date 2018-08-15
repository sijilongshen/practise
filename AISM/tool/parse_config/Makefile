
ifeq ($(strip $(BASEDIR)),)
BASEDIR=../..
endif

ifeq ($(mode),debug)
DEBUG_FLAGS=-g -DDEBUG_FLAG
endif

SOURCES = parse_config.c
OBJECTS = $(SOURCES:.c=.o)
INCLUDE = $(BASEDIR)/include

.PHONY:all clean

target=libparse_config.a

all:$(target) test

$(target):$(OBJECTS)
	ar cr $(target) $(OBJECTS)

test:test.c $(OBJECTS)
	$(CC) $(DEBUG_FLAGS) $(GLOBAL_FLAGS) -o test test.c $(OBJECTS) -I$(INCLUDE) -L. -lparse_config

%.o: %.c
	$(CC) $(DEBUG_FLAGS) $(GLOBAL_FLAGS) -c $< -I$(INCLUDE)

%.o: %.cpp
	$(CXX) $(DEBUG_FLAGS) $(GLOBAL_FLAGS) -c $< -I$(INCLUDE)

install:
	cp -f $(target) $(BASEDIR)/lib

clean:
	-rm -f test $(target) *.o

