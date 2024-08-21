NAME := shadow_pgt

KPATH := /lib/modules/$(shell uname -r)/build

obj-m += shadow_pgt.o
shadow_pgt-objs := src/shadow_pgt_linux.o src/shadow_pgt.o src/shadow_pgt_riscv.o

ccflags-y += -O2 -g

.PHONY: all
all:
	make -C $(KPATH) M=$(CURDIR) modules

.PHONY: clean
clean:
	make -C $(KPATH) M=$(CURDIR) clean
	rm $(NAME)

.PHONY: unload
unload:
	@sudo rmmod $(NAME) &> /dev/null || true

.PHONY: all
load: unload all
	# Be at least somewhat prepared for possible kernel death
	@sync
	@sudo modprobe ./$(NAME).ko

#
# Userspace testing
#

user-srcs := src/shadow_pgt_user.c src/shadow_pgt.c

user-warns := -Wall -Wextra -Wshadow -Wvla -Wpointer-arith -Walloca -Wduplicated-cond \
-Wtrampolines -Wlarger-than=1048576 -Wframe-larger-than=32768 -Wdouble-promotion -Werror=return-type

.PHONY: user
user:
	$(CC) -O2 -g -fsanitize=address $(user-srcs) $(user-warns) -o $(NAME)
	./$(NAME)
