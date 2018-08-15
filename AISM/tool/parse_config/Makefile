
ifeq ($(strip $(BASEDIR)),)
BASEDIR=../..
endif

ifeq ($(mode),debug)
DEBUG_SWITCH=-g -DDEBUG_SWITCH
endif

SOURCES = parse_config.c
OBJECTS = $(SOURCES:.c=.o)
INCLUDE = $(BASEDIR)/include

.PHONY:all clean

target=libparse_config.a

all:$(target)

$(target):$(OBJECTS)
	ar cr $(target) $(OBJECTS)

test:test.c $(target) $(OBJECTS)
	$(CC) $(DEBUG_SWITCH) $(GLOBAL_FLAGS) -o test test.c $(OBJECTS) -I$(INCLUDE) -L. -lparse_config

%.o: %.c
	$(CC) $(DEBUG_SWITCH) $(GLOBAL_FLAGS) -c $< -I$(INCLUDE)

%.o: %.cpp
	$(CXX) $(DEBUG_SWITCH) $(GLOBAL_FLAGS) -c $< -I$(INCLUDE)

install:
	cp -f $(target) $(BASEDIR)/lib

clean:
	-rm -f test $(target) *.o

