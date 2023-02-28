#include "disasm.h"
#include <iostream>
#include <elfio/elfio.hpp>
#include "cfg.h"
#include "analysis.h"
#include "reg-alloc.h"

int fastrand() { 
	static int g_seed;
	g_seed = (214013*g_seed+2531011); 
	return (g_seed>>16)&0x7FFF; 
}

static void replace_reg(basic_block& bb, std::map<vreg, int>& replace_map) {
	if (bb.visited)
		return;

	for (vins& in : bb) {
		for (vreg& reg : in.regs) {
			auto f = replace_map.find(reg);
			if (f != replace_map.end()) {
				reg.num = f->second;
			}
		}
	}

	bb.visited = true;

	for (basic_block* succ : bb.successors) {
		if (succ)
			replace_reg(*succ, replace_map);
	}
}

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

	int vnum = 16;
	for (auto& bb : cfg) {
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
			if (it->live_regs.size() < 8) {
				bb.insert(it, vins::ins_mov(vnum, 0xff));
				bb.insert(it, vins::ins_add(vnum, vnum, vnum));
				vnum++;
				break;
			}
		}
	}

	liveness_analysis(cfg);
	stack_offset_analysis(cfg);

	for (auto& bb : cfg) {
		if (!bb.name().empty()) {
			std::map<vreg, int> alloc = register_allocate(cfg, bb);
			cfg.reset();
			replace_reg(bb, alloc);
		}
	}

	lift.instructions = cfg_dump(cfg);
	
	try { lift.save(argv[argc-1]); }
	catch (std::runtime_error& e) {
		std::cout << e.what() << '\n';
		return 1;
	}
}
