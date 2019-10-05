obj-m += sys_cpenc.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

ULIBS= -lssl -lcrypto
all: xcpenc cpenc

xcpenc: xcpenc.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi xcpenc.c -o xcpenc $(ULIBS)

cpenc:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f xcpenc *.o
