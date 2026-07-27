obj-m += aerospace.o

# Kernel build tree to compile against. Defaults to the running kernel's
# headers (native build on the target). Override for cross-compiling, e.g.:
#   make KDIR=/path/to/linux ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
