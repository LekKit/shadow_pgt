NAME := shadow_pgt

KPATH := /lib/modules/$(shell uname -r)/build

obj-m += shadow_pgt.o
shadow_pgt-objs := ./src/shadow_pgt_linux.o ./src/shadow_pgt.o ./src/shadow_pgt_riscv.o

.PHONY: all
all:
	make -C $(KPATH) M=$(CURDIR) modules

.PHONY: clean
clean:
	make -C $(KPATH) M=$(CURDIR) clean

.PHONY: unload
unload:
	@sudo rmmod $(NAME) &> /dev/null || true

.PHONY: all
load: unload all
	# Be at least somewhat prepared for possible kernel death
	@sync
	@sudo modprobe ./$(NAME).ko
