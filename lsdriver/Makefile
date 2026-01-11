# 内核模块编译（单文件简化版）
obj-m += lsdriver.o  # 直接指定模块名（对应lsdriver.c）

# 编译优化（保留你的配置）
ccflags-y += -O3
ccflags-y += -Wno-error
ccflags-y += -fno-stack-protector
ccflags-y += -fomit-frame-pointer
ccflags-y += -funroll-loops
ccflags-y += -finline-functions
ccflags-y += -fstrict-aliasing
ccflags-y += -ffunction-sections -fdata-sections

# 自动获取当前目录（适配DDK）
MDIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

all:
	@echo "=== Compiling lsdriver.ko with KDIR: $(KDIR) ==="
	make -C $(KDIR) M=$(MDIR) modules

clean:
	make -C $(KDIR) M=$(MDIR) clean

compdb:
	python3 $(MDIR)/.vscode/generate_compdb.py -O $(KDIR) $(MDIR)

.PHONY: all clean compdb
