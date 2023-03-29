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
all: $(TEST_BINARY)

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
s_ecc_platform_specific.o: ecc_platform_specific.o ../../../harden
	../../../harden $< $@
s_hmac.o: hmac.o ../../../harden
	../../../harden $< $@
s_hmac_prng.o: hmac_prng.o ../../../harden
	../../../harden $< $@
s_sha256.o: sha256.o ../../../harden
	../../../harden $< $@
s_test_aes.o: test_aes.o ../../../harden
	../../../harden $< $@
s_test_cbc_mode.o: test_cbc_mode.o ../../../harden
	../../../harden $< $@
s_test_ccm_mode.o: test_ccm_mode.o ../../../harden
	../../../harden $< $@
s_test_cmac_mode.o: test_cmac_mode.o ../../../harden
	../../../harden $< $@
s_test_ctr_mode.o: test_ctr_mode.o ../../../harden
	../../../harden $< $@
s_test_ctr_prng.o: test_ctr_prng.o ../../../harden
	../../../harden $< $@
s_test_ecc_dh.o: test_ecc_dh.o ../../../harden
	../../../harden $< $@
s_test_ecc_dsa.o: test_ecc_dsa.o ../../../harden
	../../../harden $< $@
s_test_ecc_utils.o: test_ecc_utils.o ../../../harden
	../../../harden $< $@
s_test_hmac.o: test_hmac.o ../../../harden
	../../../harden $< $@
s_test_hmac_prng.o: test_hmac_prng.o ../../../harden
	../../../harden $< $@
s_test_sha256.o: test_sha256.o ../../../harden
	../../../harden $< $@
s_utils.o: utils.o ../../../harden
	../../../harden $< $@

# Dependencies
test_aes$(DOTEXE): s_test_aes.o s_aes_encrypt.o s_aes_decrypt.o s_utils.o \
		../../startup.o ../../stdlib.o
	$(LD) $(LDFLAGS) $^ -o $@

test_cbc_mode$(DOTEXE): s_test_cbc_mode.o s_cbc_mode.o \
		s_aes_encrypt.o s_aes_decrypt.o s_utils.o ../../startup.o ../../stdlib.o
	$(LD) $(LDFLAGS) $^ -o $@

test_ctr_mode$(DOTEXE): s_test_ctr_mode.o s_ctr_mode.o \
		s_aes_encrypt.o s_utils.o ../../startup.o ../../stdlib.o
	$(LD) $(LDFLAGS) $^ -o $@

test_ctr_prng$(DOTEXE): s_test_ctr_prng.o s_ctr_prng.o \
		s_aes_encrypt.o s_utils.o ../../startup.o ../../stdlib.o
	$(LD) $(LDFLAGS) $^ -o $@

test_cmac_mode$(DOTEXE): s_test_cmac_mode.o s_aes_encrypt.o s_utils.o \
		s_cmac_mode.o ../../startup.o ../../stdlib.o
	$(LD) $(LDFLAGS) $^ -o $@

test_ccm_mode$(DOTEXE): s_test_ccm_mode.o s_aes_encrypt.o \
		s_utils.o s_ccm_mode.o ../../startup.o ../../stdlib.o
	$(LD) $(LDFLAGS) $^ -o $@

test_hmac$(DOTEXE): s_test_hmac.o s_hmac.o s_sha256.o s_utils.o \
		../../startup.o ../../stdlib.o
	$(LD) $(LDFLAGS) $^ -o $@

test_hmac_prng$(DOTEXE): s_test_hmac_prng.o s_hmac_prng.o s_hmac.o \
		s_sha256.o s_utils.o ../../startup.o ../../stdlib.o
	$(LD) $(LDFLAGS) $^ -o $@

test_sha256$(DOTEXE): s_test_sha256.o s_sha256.o s_utils.o \
		../../startup.o ../../stdlib.o
	$(LD) $(LDFLAGS) $^ -o $@

test_ecc_dh$(DOTEXE): s_test_ecc_dh.o s_ecc.o s_ecc_dh.o s_test_ecc_utils.o s_ecc_platform_specific.o
	touch $@
#	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@

test_ecc_dsa$(DOTEXE): s_test_ecc_dsa.o s_ecc.o s_utils.o s_ecc_dh.o \
		s_ecc_dsa.o s_sha256.o s_test_ecc_utils.o s_ecc_platform_specific.o
#	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@
	touch $@


-include $(TEST_DEPS)
