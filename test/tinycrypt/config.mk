################################################################################
#
#      Copyright (C) 2017 by Intel Corporation, All Rights Reserved.
#
#            Global configuration Makefile. Included everywhere.
#
################################################################################

CLANG_DIRECTORY=~/Dev/LLVMEmbeddedToolchainForArm-15.0.2-Linux-x86_64/bin/
# EDIT HERE:
CC=~/Dev/LLVMEmbeddedToolchainForArm-15.0.2-Linux-x86_64/bin/clang
LD=~/Dev/LLVMEmbeddedToolchainForArm-15.0.2-Linux-x86_64/bin/clang

# Compiler flags
CFLAGS  = -Wall -Wextra -Werror
CFLAGS += --config ~/Dev/LLVMEmbeddedToolchainForArm-15.0.2-Linux-x86_64/bin/armv7m_soft_nofp.cfg
CFLAGS +=-std=c99 -D_ISOC99_SOURCE -MMD -I../lib/include/ -I../lib/source/ -I../tests/include/
CFLAGS +=-I ~/Dev/LLVMEmbeddedToolchainForArm-15.0.2-Linux-x86_64/lib/clang-runtimes/armv7m_soft_nofp/include
CFLAGS += -ffreestanding -fno-builtin -Os

LDFLAGS = -nostdlib -T../../linker.ld
LDFLAGS += ~/Dev/LLVMEmbeddedToolchainForArm-15.0.2-Linux-x86_64/lib/clang-runtimes/armv7m_soft_nofp/lib/libclang_rt.builtins-armv7m.a

vpath %.c ../lib/source/
ENABLE_TESTS=true

# override MinGW built-in recipe
%.o: %.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<

DOTEXE:=.elf

# DO NOT EDIT AFTER THIS POINT:
ifeq ($(ENABLE_TESTS), true)
CFLAGS += -DENABLE_TESTS
else
CFLAGS += -DDISABLE_TESTS
endif

export CC
export CFLAGS
export VPATH
export ENABLE_TESTS
export LDFLAGS
export LD

################################################################################
