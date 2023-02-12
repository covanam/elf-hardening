#include "disasm.h"
#include <iostream>
#include <elfio/elfio.hpp>
int main(int argc, char *argv[]) {
	ELFIO::elfio reader;
	reader.load(argv[1]);

	lifter lift(reader);

	lift.construct_labels();

	for (const vins &c : lift.instructions) {
		std::cout << std::hex << '[' << c.addr << "] " << std::dec;

		std::cout << c << '\n';
	}

	dump_text(reader, lift.instructions);

	reader.save(argv[2]);
}
