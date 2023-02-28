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

	for (auto it = lift.instructions.begin(); it != lift.instructions.end();) {
		auto next = std::next(it);
		if (it->mnemonic == "cbnz") {
			vins& cbnz = *it;
			vins temp = vins::ins_cmp(cbnz.regs[0], 0);
			temp.addr = cbnz.addr;
			temp.label = cbnz.label;
			lift.instructions.insert(it, std::move(temp));
			temp = vins::ins_b("ne", cbnz.target_label.c_str());
			lift.instructions.insert(it, std::move(temp));
			lift.instructions.erase(it);
		}
		else if (it->mnemonic == "cbz") {
			vins& cbnz = *it;
			vins temp = vins::ins_cmp(cbnz.regs[0], 0);
			temp.addr = cbnz.addr;
			temp.label = cbnz.label;
			lift.instructions.insert(it, std::move(temp));
			temp = vins::ins_b("eq", cbnz.target_label.c_str());
			lift.instructions.insert(it, std::move(temp));
			lift.instructions.erase(it);
		}
		it = next;
	}

	control_flow_graph cfg = get_cfg(lift.instructions);
	liveness_analysis(cfg);

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
