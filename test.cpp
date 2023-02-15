#include "disasm.h"
#include <iostream>
#include <elfio/elfio.hpp>
int fastrand() { 
	static int g_seed;
	g_seed = (214013*g_seed+2531011); 
	return (g_seed>>16)&0x7FFF; 
}

int main(int argc, char *argv[]) {
	lifter lift;
	if (!lift.load(argv[1])) {
		std::cerr << "Cannot open input file " << argv[1] << '\n';
		return 1;
	}

	int skip = 0;
	for (auto vi = lift.instructions.begin(); vi != lift.instructions.end();) {
		auto next = std::next(vi);
		if (skip) {
			skip--;
			goto giangngu;
		}
		if (vi->mnemonic[0] == 'i' && vi->mnemonic[1] == 't') {
			skip = 4;
			goto giangngu;
		}
		if (vi->in.id) {
			if (fastrand() % 2) {
				lift.instructions.insert(vi, vins("nop"));
			}
		}
		giangngu:
		vi = next;
	}

	/*
	for (const vins &c : lift.instructions) {
		if (c.is_original)
			std::cout << std::hex << '[' << c.addr << "] " << std::dec;

		std::cout << c << '\n';
	}
	*/

	if (!lift.save(argv[argc-1])) {
		std::cerr << "Cannot open output file: " << argv[argc-1] << '\n';
		return 1;
	}
}
