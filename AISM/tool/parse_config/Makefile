
SOURCES = parse_config.c
OBJECTS = $(SOURCES:.c=.o)
INCLUDE = $(BASEDIR)/depend/include

.PHONY:all clean

target=libparse_config.a

all:$(target) 

$(target):$(OBJECTS)
	@echo "-- compiling $(target) : $(OBJECTS)-- "
	ar cr $(target) $(OBJECTS)

%.o: %.c
	$(CC) -c $< -I$(INCLUDE)

%.o: %.cpp
	$(CXX) -c $< -I$(INCLUDE)

install:
	cp -f $(target) $(BASEDIR)/depend/lib

clean:
	-rm -f $(target) *.o

