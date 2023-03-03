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

	for (auto cfgi = cfg.begin(); cfgi != cfg.end(); ++cfgi) {
		auto& bb = *cfgi;
		if (bb.front().is_data())
			continue;
		int skip = 0;

		for (auto it = ++bb.begin(); it != bb.end(); ++it) {
			if (!it->mnemonic.compare(0, 2, "it", 2)) {
				skip = 4;
				continue;
			}
			if (skip) {
				skip--;
				continue;
			}
			vreg free_reg = vreg();
			for (free_reg.num = 0; free_reg.num < 16; free_reg.num++) {
				if (it->live_regs.find(free_reg) == it->live_regs.end())
					break;
			}
			if (free_reg.num == 16 || free_reg.num == 13 || free_reg.num == 15)
				continue;
			bb.insert(it, vins::ins_mov(free_reg, 0xff));
                }
	}

	lift.instructions = cfg_dump(cfg);
	
	try { lift.save(argv[argc-1]); }
	catch (std::runtime_error& e) {
		std::cout << e.what() << '\n';
		return 1;
	}
}
