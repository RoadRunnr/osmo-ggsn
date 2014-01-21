CC=gcc
KDIR := /lib/modules/$(shell uname -r)/build

obj-m += gtp.o

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
	$(CC) -lmnl gtp-link-add.c -o gtp-link-add
	$(CC) -lmnl gtp-tunnel-add.c genl.c -o gtp-tunnel-add
clean:
	rm -rf *.o *.mod.* modules.order Module.symvers *.ko .tmp_versions .*.cmd
	rm -f genl-family-get gtp-link-add gtp-tunnel-add
