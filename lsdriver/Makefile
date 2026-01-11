
MODULE_NAME := lsdriver
$(MODULE_NAME)-objs := lsdriver.o
obj-m := $(MODULE_NAME).o

#O3
ccflags-y += -O3

# 将所有警告降级，不再视为错误
ccflags-y += -Wno-error

#禁用栈保护
ccflags-y += -fno-stack-protector

#省略帧指针
ccflags-y += -fomit-frame-pointer

# 循环展开: 牺牲二进制体积，减少 while/for 循环的跳转和判断开销
ccflags-y += -funroll-loops


# 强制内联: 消除函数调用 (call/ret) 和参数压栈的开销
ccflags-y += -finline-functions


# 严格别名优化: 允许编译器假设不同类型的指针指向不同内存，从而进行更激进的指令重排
ccflags-y += -fstrict-aliasing



# 死代码消除辅助: 将每个函数和数据放入独立段，配合链接器剔除无用代码
ccflags-y += -ffunction-sections -fdata-sections



# 注释这行为release编译，不会有pr_debug输出
#ccflags-y += -DDEBUG
KDIR := $(KDIR)
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
all:
	make -C $(KDIR) M=$(MDIR) modules

clean:
	make -C $(KDIR) M=$(MDIR) clean
    
compdb:
	python3 $(MDIR)/.vscode/generate_compdb.py -O $(KDIR) $(MDIR)

.PHONY: all clean