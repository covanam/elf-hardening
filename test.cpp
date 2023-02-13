#include "disasm.h"
#include <iostream>
#include <elfio/elfio.hpp>
int fastrand() { 
	static int g_seed;
	g_seed = (214013*g_seed+2531011); 
	return (g_seed>>16)&0x7FFF; 
}

int main(int argc, char *argv[]) {
	lifter lift(argv[1]);

	fastrand();fastrand();

	for (auto vi = lift.instructions.begin(); vi != lift.instructions.end();) {
		auto next = std::next(vi);
		if (vi->in.id) {
			if (fastrand() % 2) {
				lift.instructions.insert(vi, vins("nop"));
			}
		}
		vi = next;
	}

	for (const vins &c : lift.instructions) {
		if (c.is_original)
			std::cout << std::hex << '[' << c.addr << "] " << std::dec;

		std::cout << c << '\n';
	}

	lift.save(argv[2]);
}
