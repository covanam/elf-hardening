#include "disasm.h"
#include <iostream>
#include <elfio/elfio.hpp>
int main(int argc, char *argv[]) {
	ELFIO::elfio reader;
	reader.load(argv[1]);
        std::list<bunit> x;
        x = disassemble(reader);

        for (const bunit &c : x) {
                if (c.in.id == 0) {
                        std::cout << '[' << c.addr << "] some data\n";
                } else {
                        std::cout << c << '\n';
                }
        }
        
        dump_text(reader, x);

        reader.save(argv[2]);
}
