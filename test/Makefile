CC=arm-none-eabi-gcc

CFLAGS  = -Wall -Wextra -Werror
CFLAGS += -mthumb -march=armv7-m
CFLAGS += -ffreestanding

all: startup.o stdlib.o second_stack.o
	make -C tinycrypt

clean:
	rm *.o
	make -C tinycrypt clean
