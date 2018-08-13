
SOURCES = parse_config.c
OBJECTS = $(SOURCES:.c=.o)
INCLUDE = $(BASEDIR)/depend/include

.PHONY:all clean

target=libparse_config.a

all:$(target) test

$(target):$(OBJECTS)
	ar cr $(target) $(OBJECTS)

test:test.c $(OBJECTS)
	$(CC) -o test test.c $(OBJECTS) -I$(INCLUDE) -L. -lparse_config

%.o: %.c
	$(CC) -c $< -I$(INCLUDE)

%.o: %.cpp
	$(CXX) -c $< -I$(INCLUDE)

install:
	cp -f $(target) $(BASEDIR)/depend/lib

clean:
	-rm -f test $(target) *.o

