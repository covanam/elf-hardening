CC=~/Dev/LLVMEmbeddedToolchainForArm-15.0.2-Linux-x86_64/bin/clang

CFLAGS  = -Wall -Wextra -Werror
CFLAGS += -ffreestanding
CFLAGS += --config ~/Dev/LLVMEmbeddedToolchainForArm-15.0.2-Linux-x86_64/bin/armv7m_soft_nofp.cfg
CFLAGS +=-Os -std=c99

all: startup.o stdlib.o second_stack.o
	make -C tinycrypt

clean:
	rm *.o
	make -C tinycrypt clean
