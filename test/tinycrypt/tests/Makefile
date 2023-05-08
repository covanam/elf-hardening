################################################################################
#
#      Copyright (C) 2017 by Intel Corporation, All Rights Reserved.
#
# 								           Tests Makefile.
#
################################################################################

include ../config.mk

TEST_LIB_FILE:=test_ecc_utils.c
TEST_SOURCE:=$(filter-out $(TEST_LIB_FILE), $(wildcard test_*.c))

TEST_OBJECTS:=$(TEST_SOURCE:.c=.o)
TEST_DEPS:=$(TEST_SOURCE:.c=.d)
TEST_BINARY:=$(TEST_SOURCE:.c=$(DOTEXE))

# Edit the 'all' content to add/remove tests needed from TinyCrypt library:
all: \
	secboot_sha256_000.elf secboot_sha256_001.elf secboot_sha256_010.elf \
	secboot_sha256_011.elf secboot_sha256_100.elf secboot_sha256_101.elf \
	secboot_sha256_110.elf secboot_sha256_111.elf 

clean:
	-$(RM) $(TEST_BINARY) $(TEST_OBJECTS) $(TEST_DEPS)
	-$(RM) *~ *.o *.d

s_sha256.o: sha256.o ../../../harden
	../../../harden $< $@
s_utils.o: utils.o ../../../harden
	../../../harden $< $@
s_secboot_sha256.o: secboot_sha256.o ../../../harden
	../../../harden $< $@

# Dependencies
secboot_sha256_000$(DOTEXE): sha256.o utils.o secboot_sha256.o \
		../../startup.o ../../second_stack.o
	$(LD) $(LDFLAGS) $^ -o $@

secboot_sha256_001$(DOTEXE): sha256.o utils.o s_secboot_sha256.o \
		../../startup.o ../../second_stack.o
	$(LD) $(LDFLAGS) $^ -o $@

secboot_sha256_010$(DOTEXE): sha256.o s_utils.o secboot_sha256.o \
		../../startup.o ../../second_stack.o
	$(LD) $(LDFLAGS) $^ -o $@

secboot_sha256_011$(DOTEXE): sha256.o s_utils.o s_secboot_sha256.o \
		../../startup.o ../../second_stack.o
	$(LD) $(LDFLAGS) $^ -o $@

secboot_sha256_100$(DOTEXE): s_sha256.o utils.o secboot_sha256.o \
		../../startup.o ../../second_stack.o
	$(LD) $(LDFLAGS) $^ -o $@

secboot_sha256_101$(DOTEXE): s_sha256.o utils.o s_secboot_sha256.o \
		../../startup.o ../../second_stack.o
	$(LD) $(LDFLAGS) $^ -o $@

secboot_sha256_110$(DOTEXE): s_sha256.o s_utils.o secboot_sha256.o \
		../../startup.o ../../second_stack.o
	$(LD) $(LDFLAGS) $^ -o $@

secboot_sha256_111$(DOTEXE): s_sha256.o s_utils.o s_secboot_sha256.o \
		../../startup.o ../../second_stack.o
	$(LD) $(LDFLAGS) $^ -o $@

-include $(TEST_DEPS)
