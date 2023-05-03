BUILDDIR=$(CURDIR)/build
PWD := $(CURDIR) 
obj-m += sniffer.o

all: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 
 
clean: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
