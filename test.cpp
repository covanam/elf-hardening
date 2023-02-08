#include "disasm.h"
#include <iostream>
#include <elfio/elfio.hpp>
int main(int argc, char *argv[]) {
	ELFIO::elfio reader;
	reader.load(argv[1]);

	lifter lift(reader);

        lift.construct_labels();

	for (const bunit &c : lift.instructions) {
                std::cout << std::hex << '[' << c.addr << "] " << std::dec;

                std::cout << c << '\n';
        }

/*
        for (auto i = x.begin(); i != x.end(); ++i) {
                if (i->in.id != 0) {
                        uint64_t addr = i->addr;
                        bunit nop("nop", addr);
                        x.insert(i, nop);
                        break;
                }
        }

        fix_address(x);

        for (const bunit &c : x) {
                std::cout << std::hex << '[' << c.addr << "] " << std::dec;
                if (c.in.id == 0) {
                        std::cout << "some data\n";
                } else {
                        std::cout << c << '\n';
                }
        }
        
        dump_text(reader, x);

        reader.save(argv[2]);
*/
}
