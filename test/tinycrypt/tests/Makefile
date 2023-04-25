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
all: $(TEST_BINARY) secboot_sha256.elf secboot_hmac.elf secboot_ecc_dsa.elf \
	naked_secboot_sha256.elf naked_secboot_hmac.elf naked_secboot_ecc_dsa.elf

clean:
	-$(RM) $(TEST_BINARY) $(TEST_OBJECTS) $(TEST_DEPS)
	-$(RM) *~ *.o *.d

s_aes_decrypt.o: aes_decrypt.o ../../../harden
	../../../harden $< $@
s_aes_encrypt.o: aes_encrypt.o ../../../harden
	../../../harden $< $@ 
s_cbc_mode.o: cbc_mode.o ../../../harden
	../../../harden $< $@
s_ccm_mode.o: ccm_mode.o ../../../harden
	../../../harden $< $@
s_cmac_mode.o: cmac_mode.o ../../../harden
	../../../harden $< $@
s_ctr_mode.o: ctr_mode.o ../../../harden
	../../../harden $< $@
s_ctr_prng.o: ctr_prng.o ../../../harden
	../../../harden $< $@
s_ecc_dh.o: ecc_dh.o ../../../harden
	../../../harden $< $@
s_ecc_dsa.o: ecc_dsa.o ../../../harden
	../../../harden $< $@
s_ecc.o: ecc.o ../../../harden
	../../../harden $< $@
s_hmac.o: hmac.o ../../../harden
	../../../harden $< $@
s_hmac_prng.o: hmac_prng.o ../../../harden
	../../../harden $< $@
s_sha256.o: sha256.o ../../../harden
	../../../harden $< $@
s_utils.o: utils.o ../../../harden
	../../../harden $< $@
s_secboot_sha256.o: secboot_sha256.o ../../../harden
	../../../harden $< $@
s_secboot_hmac.o: secboot_hmac.o ../../../harden
	../../../harden $< $@
s_secboot_ecc_dsa.o: secboot_ecc_dsa.o ../../../harden
	../../../harden $< $@

# Dependencies
test_aes$(DOTEXE): test_aes.o s_aes_encrypt.o s_aes_decrypt.o s_utils.o \
		../../startup.o ../../stdlib.o ../../second_stack.o
	$(LD) $(LDFLAGS) $^ -o $@

test_cbc_mode$(DOTEXE): test_cbc_mode.o s_cbc_mode.o \
		s_aes_encrypt.o s_aes_decrypt.o s_utils.o ../../startup.o ../../stdlib.o ../../second_stack.o
	$(LD) $(LDFLAGS) $^ -o $@

test_ctr_mode$(DOTEXE): test_ctr_mode.o s_ctr_mode.o \
		s_aes_encrypt.o s_utils.o ../../startup.o ../../stdlib.o ../../second_stack.o
	$(LD) $(LDFLAGS) $^ -o $@

test_ctr_prng$(DOTEXE): test_ctr_prng.o s_ctr_prng.o \
		s_aes_encrypt.o s_utils.o ../../startup.o ../../stdlib.o ../../second_stack.o
	$(LD) $(LDFLAGS) $^ -o $@

test_cmac_mode$(DOTEXE): test_cmac_mode.o s_aes_encrypt.o s_utils.o \
		s_cmac_mode.o ../../startup.o ../../stdlib.o ../../second_stack.o
	$(LD) $(LDFLAGS) $^ -o $@

test_ccm_mode$(DOTEXE): test_ccm_mode.o s_aes_encrypt.o \
		s_utils.o s_ccm_mode.o ../../startup.o ../../stdlib.o ../../second_stack.o
	$(LD) $(LDFLAGS) $^ -o $@

test_hmac$(DOTEXE): test_hmac.o s_hmac.o s_sha256.o s_utils.o \
		../../startup.o ../../stdlib.o ../../second_stack.o
	$(LD) $(LDFLAGS) $^ -o $@

test_hmac_prng$(DOTEXE): test_hmac_prng.o s_hmac_prng.o s_hmac.o \
		s_sha256.o s_utils.o ../../startup.o ../../stdlib.o ../../second_stack.o
	$(LD) $(LDFLAGS) $^ -o $@

test_sha256$(DOTEXE): test_sha256.o s_sha256.o s_utils.o \
		../../startup.o ../../stdlib.o ../../second_stack.o
	$(LD) $(LDFLAGS) $^ -o $@

secboot_sha256$(DOTEXE): s_secboot_sha256.o s_sha256.o s_utils.o \
		../../startup.o ../../stdlib.o ../../second_stack.o
	$(LD) $(LDFLAGS) $^ -o $@

secboot_hmac$(DOTEXE): s_secboot_hmac.o s_hmac.o s_sha256.o s_utils.o \
		../../startup.o ../../stdlib.o ../../second_stack.o
	$(LD) $(LDFLAGS) $^ -o $@

secboot_ecc_dsa$(DOTEXE): s_secboot_ecc_dsa.o s_ecc_dsa.o s_ecc.o s_utils.o \
		s_sha256.o ../../startup.o ../../stdlib.o ../../second_stack.o
	$(LD) $(LDFLAGS) $^ -o $@

naked_secboot_sha256$(DOTEXE): secboot_sha256.o sha256.o utils.o \
		../../startup.o ../../stdlib.o ../../second_stack.o
	$(LD) $(LDFLAGS) $^ -o $@

naked_secboot_hmac$(DOTEXE): secboot_hmac.o hmac.o sha256.o utils.o \
		../../startup.o ../../stdlib.o ../../second_stack.o
	$(LD) $(LDFLAGS) $^ -o $@

naked_secboot_ecc_dsa$(DOTEXE): secboot_ecc_dsa.o ecc_dsa.o ecc.o utils.o \
		sha256.o ../../startup.o ../../stdlib.o ../../second_stack.o
	$(LD) $(LDFLAGS) $^ -o $@


-include $(TEST_DEPS)
