CC=gcc
KDIR := /lib/modules/$(shell uname -r)/build

obj-m += gtp.o

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	rm -rf *.o *.mod.* modules.order Module.symvers *.ko .tmp_versions .*.cmd
