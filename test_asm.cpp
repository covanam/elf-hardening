#include <keystone/keystone.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>

static bool sym_resolver(const char *symbol, uint64_t *value)
{
        *value = 0;
        return true;
}

std::vector<uint8_t> assemble(const std::string &s) {
	std::vector<uint8_t> ret;
	ks_engine *ks;
	ks_err err;
	size_t count;
	unsigned char *encode;
	size_t size;

	err = ks_open(KS_ARCH_ARM, KS_MODE_THUMB, &ks);
	if (err != KS_ERR_OK) {
		goto open_fail;
	}

        //ks_option(ks, KS_OPT_SYM_RESOLVER, (size_t)sym_resolver);
  
	if (ks_asm(ks, s.c_str(), 0, &encode, &size, &count) != KS_ERR_OK) {
		goto asm_fail;
	} else if (count == 0 && s.length() != 0) {
		goto asm_fail;
	} else {
		ret.assign(encode, encode + size);
	}

	// NOTE: free encode after usage to avoid leaking memory
	ks_free(encode);

	// close Keystone instance when done
	ks_close(ks);

	return ret;

asm_fail:
	err = ks_errno(ks);
	ks_close(ks);
open_fail:
	std::cout << "Trying to assemble:\n" << s;
	std::string msg = "Assembling failed: ";
	msg.append(ks_strerror(err));
	throw std::runtime_error(msg);
}

int main() {
        std::ifstream t("ngu.txt");
        std::stringstream buffer;
        buffer << t.rdbuf();

        assemble(buffer.str());
}