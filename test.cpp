#include "disasm.h"
#include <iostream>
#include <elfio/elfio.hpp>
#include "cfg.h"
#include "analysis.h"
#include "reg-alloc.h"
#include <iomanip>

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
		replace_reg(*succ, replace_map);
	}

	for (basic_block* pred : bb.predecessors) {
		replace_reg(*pred, replace_map);
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

	control_flow_graph cfg = get_cfg(lift);
	
	std::cout << "\nOriginal:------------------------------------------\n";
	for (auto& bb : cfg) {
		for (auto& in : bb) {
			std::cout << std::setw(25) << std::setfill('0') << in.addr << ' ' << in << '\n';
		}
	}

	for (auto it_bb = cfg.begin(); it_bb != cfg.end(); ++it_bb) {
		basic_block& entry = *it_bb;
		if (entry.front().is_data())
			continue;
		if (entry.front().label == *lift.functions.begin()) {
			vins tmp = vins::ins_mov(17, 321);
			entry.insert(std::next(entry.begin()), std::move(tmp));
			tmp = vins::ins_mov(18, 123);
			entry.insert(std::next(entry.begin()), std::move(tmp));

			for (auto it = it_bb;; ++it) {
				basic_block& bb = *it;
				for (auto in = ++bb.begin(); in != bb.end();) {
					auto next = std::next(in);
					if (fastrand() % 32 == 0) {
						vins tmp = vins::ins_add(vreg(17), vreg(16), 99);
						bb.insert(in, std::move(tmp));
						tmp = vins::ins_sub(vreg(16), vreg(17), 98);
						bb.insert(in, std::move(tmp));
					}
					in = next;

					if (next->is_function_return())
						break;
				}

				if (std::next(it) == cfg.end())
					break;

				if (std::next(it)->front().is_data())
					break;
				
				if (std::next(it)->front().is_pseudo() &&
					std::next(it)->front().operands == "func_entry")
					break;
			}

			break;
		}
	}

	split_registers(cfg, *lift.functions.begin());
	
	std::cout << "\nSplit:------------------------------------------\n";
	for (auto& bb : cfg) {
		for (auto& in : bb) {
			std::cout << std::setw(25) << std::setfill('0') << in.addr << ' ' << in << '\n'; //<< "\t(";
			//for (vreg r : in.regs) {
		//		std::cout << r << ' ';
		//	}
		//	std::cout << ")\n";
		}
	}

	liveness_analysis(cfg);
	std::cout << "\nLiveness:------------------------------------------\n";
	for (auto& bb : cfg) {
		for (auto& in : bb) {
			std::cout << in << "\t(";
			for (vreg r : in.live_regs) {
				std::cout << r << ' ';
			}
			std::cout << ")\n";
		}
	}

	for (auto& bb : cfg) {
		if (bb.is_entry()) {
			std::map<vreg, int> alloc = register_allocate(cfg, bb);
			std::cout << bb.front() << '\n';
			std::cout << "\nAlloc for " << bb.front().label << "--------------------------\n";

			for (const auto& ngu : alloc) {
				std::cout << '\t' << ngu.first << " -> " << ngu.second << '\n';
			}

			cfg.reset();
			replace_reg(bb, alloc);
		}
	}

	std::cout << "\nAllocate:--------------------------\n";
	for (auto& bb : cfg) {
		for (auto& in : bb) {
			std::cout << std::setw(25) << std::setfill('0') << in.addr << ' ' << in << '\n';
		}
	}

	spill(cfg);

	std::cout << "\nSpilled:--------------------------\n";
	for (auto& bb : cfg) {
		for (auto& in : bb) {
			std::cout << std::setw(25) << std::setfill('0') << in.addr << ' ' << in << '\n';;
		}
	}
	
	lift.instructions = cfg_dump(cfg);
	
	try { lift.save(argv[argc-1]); }
	catch (std::runtime_error& e) {
		std::cout << e.what() << '\n';
		return 1;
	}
}
