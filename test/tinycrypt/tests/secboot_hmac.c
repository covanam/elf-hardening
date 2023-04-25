#include <tinycrypt/hmac.h>
#include <test_utils.h>
#include <stdint.h>

static const uint8_t secret_key[4] = {
	0x4a, 0x65, 0x66, 0x65
};

const uint8_t firmware[28] = {
	0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77,
	0x61, 0x6e, 0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68,
	0x69, 0x6e, 0x67, 0x3f
};

static const uint8_t reference_tag[32] = {
	0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26,
	0x08, 0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
	0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
};

int compare(const uint8_t *s1, const uint8_t *s2, uint32_t len) {
	while (len--)
		if (*(s1++) != *(s2++))
			return 1;
	return 0;
}

__attribute__((noinline)) void execute_firmware() {
	TC_END_REPORT(TC_PASS);
}

__attribute__((noinline)) void abort_boot() {
	TC_END_REPORT(TC_FAIL);
}

int my_main() {
	struct tc_hmac_state_struct state;
	uint8_t computed_tag[32];

	tc_hmac_set_key(&state, secret_key, sizeof(secret_key));

	tc_hmac_init(&state);
	tc_hmac_update(&state, firmware, sizeof(firmware));
	tc_hmac_final(computed_tag, 32, &state);

	if (compare(computed_tag, reference_tag, 32)) {
		abort_boot();
	}
	else {
		execute_firmware();
	}
	return 0;
}

int main() { return my_main(); }
