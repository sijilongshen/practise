
BASEDIR=$(PWD)

## 是否打开调试开关 ##
ifeq ($(mode),debug)
DEBUG_SWITCH=-g -DDEBUG_SWITCH
endif

## foreach 会将两次逻辑返回的信息合并到一起 ##
## 所以一定要在最开始放一个空行，分隔两次的数据 ##
define func_make

@if [ "$(1)" = "all" ]; then \
echo "---- make $(2) ----"; \
else \
echo "---- $(1) $(2) ----"; \
fi ;
@if [ "$(1)" = "all" ]; then \
make -C $(BASEDIR)/$(2) ; \
else \
make $(1) -C $(BASEDIR)/$(2) ; \
fi ;
endef 

CC =gcc
CXX=g++

## 全局公用的宏定义 ##
GLOBAL_FLAGS=

export BASEDIR DEBUG_SWITCH CC CXX GLOBAL_FLAGS

target_dir=tool/parse_config client server

.PHONY: default
default: all

all:
	@echo "basedir      : $(BASEDIR)     "
	@echo "compile mode : $(COMPILI_MODE)"
	@echo "-------------------------------------------------------"
	$(foreach dir, $(target_dir), $(call func_make,all,$(dir)))

install:
	$(foreach dir, $(target_dir), $(call func_make,install,$(dir)))

clean:
	rm -f bin/* lib/*
	$(foreach dir, $(target_dir), $(call func_make,clean,$(dir)))

