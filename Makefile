obj-y := crypt.o
obj-m += sys_crypt.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -Wall -Werror cipher.c -lssl 
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

