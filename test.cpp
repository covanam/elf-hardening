#include "disasm.h"
#include <iostream>
#include <elfio/elfio.hpp>
int main(int argc, char *argv[]) {
	lifter lift(argv[1]);

	for (const vins &c : lift.instructions) {
		std::cout << std::hex << '[' << c.addr << "] " << std::dec;

		std::cout << c << '\n';
	}

	lift.save(argv[2]);
}
