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

	try { lift.save(argv[argc-1]); }
	catch (std::runtime_error& e) {
		std::cout << e.what() << '\n';
		return 1;
	}
}
