#include "disasm.h"
#include <iostream>
#include <elfio/elfio.hpp>
#include "cfg.h"
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

	control_flow_graph cfg = get_cfg(lift.instructions);
	liveness_analysis(cfg);
	lift.instructions = cfg_dump(cfg);
	
	int skip = 0;
	for (auto vi = lift.instructions.begin(); vi != lift.instructions.end();) {
		auto next = std::next(vi);
		if (vi->mnemonic[0] == 'i' && vi->mnemonic[1] == 't') {
			if (skip < 4)
				skip = 4;
			goto giangngu;
		}
		if (!vi->mnemonic.compare(0, 2, "cb", 2)) {
			skip = 128;
			goto giangngu;
		}
		if (skip) {
			skip--;
			goto giangngu;
		}
		if (vi->in.id) {
			if (fastrand() % 2 == 0) {
				vreg free_reg = vreg();
				for (free_reg.num = 0; free_reg.num < 16; free_reg.num++) {
					if (vi->live_regs.find(free_reg) == vi->live_regs.end())
						break;
				}
				if (free_reg.num == 16 || free_reg.num == 13 || free_reg.num == 15)
					continue;
				vins tmp("mov", "%0, #0xff", {free_reg});
				lift.instructions.insert(vi, tmp);
			}
		}
		giangngu:
		vi = next;
	}
	
	try { lift.save(argv[argc-1]); }
	catch (std::runtime_error& e) {
		std::cout << e.what() << '\n';
		return 1;
	}
}
