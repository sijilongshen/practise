
BASEDIR=$(PWD)

COMPILI_MODE=release
ifdef mode
ifeq ("$(origin mode)", "command line")
COMPILI_MODE=$(mode)
endif
endif

## foreach 会将两次逻辑返回的信息合并到一起 ##
## 所以一定要在最开始放一个空行，分隔两次的数据 ##
define func_make

@echo "---- compile $(1) ----"
make -C $(BASEDIR)/$(1)
make install -C $(BASEDIR)/$(1)
endef 

define func_clean

@echo "---- clean $(1) ----"
make clean -C $(BASEDIR)/$(1)
endef 
CC =gcc
CXX=g++

export BASEDIR COMPILI_MODE CC CXX

target_dir=tool/parse_config client server

.PHONY: default
default: all

all:
	@echo "basedir      : $(BASEDIR)     "
	@echo "compile mode : $(COMPILI_MODE)"
	@echo "-------------------------------------------------------"
	$(foreach dir, $(target_dir), $(call func_make,$(dir)))

clean:
	$(foreach dir, $(target_dir), $(call func_clean,$(dir)))

