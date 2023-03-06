#include "disasm.h"
#include <iostream>
#include <elfio/elfio.hpp>
#include "cfg.h"
#include "analysis.h"
#include "reg-alloc.h"

int main(int argc, char *argv[]) {
	lifter lift;
	if (!lift.load(argv[1])) {
		std::cerr << "Cannot open input file " << argv[1] << '\n';
		return 1;
	}

	if (lift.instructions.empty()) {
		try {
			lift.save(argv[argc-1]);
			return 0;
		}
		catch (std::runtime_error& e) {
			std::cout << e.what() << '\n';
			return 1;
		}
	}

	control_flow_graph cfg = get_cfg(lift.instructions);
	liveness_analysis(cfg);

	try {
		cfg.reset();
		for (auto& bb : cfg) {
			if (bb.front().label.size() && bb.front().label[0] != '.') {
				stack_offset_analysis(bb);
			}
		}
	}
	catch (stack_analysis_failure &e) {
		std::cout << "Failed to analyse stack: " << e.reason() << '\n';
		return 1;
	}

	/*
	for (auto& bb : cfg) {
		for (auto& in : bb) {
			std::cout << in << "\tstack = " << in.stack_offset << '\n';
		}
	}*/
	
	lift.instructions = cfg_dump(cfg);
	
	try { lift.save(argv[argc-1]); }
	catch (std::runtime_error& e) {
		std::cout << e.what() << '\n';
		return 1;
	}
}
