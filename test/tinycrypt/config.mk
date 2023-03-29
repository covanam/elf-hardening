################################################################################
#
#      Copyright (C) 2017 by Intel Corporation, All Rights Reserved.
#
#            Global configuration Makefile. Included everywhere.
#
################################################################################

# EDIT HERE:
CC=arm-none-eabi-gcc
LD=arm-none-eabi-ld

# Compiler flags
CFLAGS  = -Wall -Wextra -Werror
CFLAGS += -mthumb -march=armv7-m
CFLAGS += -ffreestanding
CFLAGS +=-Os -std=c99 -Wall -Wextra -D_ISOC99_SOURCE -MMD -I../lib/include/ -I../lib/source/ -I../tests/include/

LDFLAGS = -nostdlib -T../../linker.ld

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
