#include "disasm.h"
#include <iostream>
#include <elfio/elfio.hpp>
#include "analysis.h"

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

	std::cout << lift.instructions.size() << '\n';
	std::list<basic_block> cfg = get_cfg(lift.instructions);
	for (auto bb : cfg) {
		std::cout << bb;
	}

	/*
	int skip = 0;
	for (auto vi = lift.instructions.begin(); vi != lift.instructions.end();) {
		auto next = std::next(vi);
		if (vi->mnemonic[0] == 'i' && vi->mnemonic[1] == 't') {
			skip = 4;
			goto giangngu;
		}
		if (vi->mnemonic.compare(0, 2, "cb", 2)) {
			skip = 128;
			goto giangngu;
		}
		if (skip) {
			skip--;
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
	*/

	/*
	int skip = 0;
	for (auto vi = lift.instructions.begin(); vi != lift.instructions.end(); ++vi) {
		std::cout << *vi << " (";
		if (!vi->is_data())
			for (int i = 0; i < vi->detail.groups_count; ++i) {
				std::cout << +vi->detail.groups[i] << ' ';
			}
		std::cout << ")\n";
	}
	*/
	/*
	try { lift.save(argv[argc-1]); }
	catch (std::runtime_error& e) {
		std::cout << e.what() << '\n';
		return 1;
	}
	*/
}
