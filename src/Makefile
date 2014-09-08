obj-m += rootkit.o
rootkit-objs := main.o c2.o rshell.o bypass_fw.o rkit_ext.o

KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
