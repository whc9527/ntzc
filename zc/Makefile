obj-m := ntzc.o 
#obj-m += pcnet.o
obj-m += igb/
ntzc-objs := bvl.o zc.o nta.o
pcnet-objs := pcnet32.o

EXTRA_CFLAGS = -g -O2

all:
	make -C /lib/modules/`uname -r`/build M=`pwd`

clean:
	make -C /lib/modules/`uname -r`/build M=`pwd` clean
