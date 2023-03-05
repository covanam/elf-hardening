#include "cfg.h"
#include "disasm.h"
#include <set>
#include <cassert>
#include "analysis.h"
#include <sstream>

static void reverse_flow(basic_block& current, std::set<vreg> live_regs) {
	for (auto i = current.rbegin(); i != current.rend(); ++i) {
		for (int j : i->gen)
			live_regs.erase(i->regs[j]);
		for (int j : i->use)
			live_regs.insert(i->regs[j]);
		
		int before = i->live_regs.size();

		i->live_regs.merge(live_regs);
		live_regs = i->live_regs;
		if (before == i->live_regs.size() && current.visited) {
			// continuing won't change anything
			return;
		}
	}

	current.visited = true;
	
	for (basic_block *p : current.predecessors)
		reverse_flow(*p, live_regs);
}

void liveness_analysis(control_flow_graph& cfg) {
	std::set<vreg> use_at_func_return = {0, 1, 4, 5, 6, 7, 8, 9, 10, 11};
	cfg.reset();
	for (auto bb = cfg.rbegin(); bb != cfg.rend(); ++bb) {
		if (bb->front().is_data())
			continue;

		if (bb->is_exit())
			reverse_flow(*bb, use_at_func_return);
	}
}

void stack_offset_forward_flow(basic_block& bb, int stack_offset) {
	if (bb.visited)
		return;
	bb.visited = true;
	for (auto& in : bb) {
		in.stack_offset = stack_offset;
		for (int i : in.gen) {
			if (in.regs[i] == 13) {
				if (in.mnemonic.rfind("add", 0) == 0) {
					if (in.use.size() != 1) {
						std::stringstream ss;
						ss << in;
						throw stack_analysis_failure(ss.str());
					}
					if (in.regs[in.use[0]] == 13) {
						stack_offset += in.imm();
						continue;
					}
				} else if (in.mnemonic.rfind("sub", 0) == 0) {
					if (in.use.size() != 1) {
						std::stringstream ss;
						ss << in;
						throw stack_analysis_failure(ss.str());
					}
					if (in.regs[in.use[0]] == 13) {
						stack_offset -= in.imm();
						continue;
					}
				} else if (in.mnemonic.rfind("ldr", 0) == 0) {
					assert(in.imm());
					stack_offset += in.imm();
					continue;
				}
				std::stringstream ss;
				ss << in;
				throw stack_analysis_failure(ss.str());
			}
		}
		if (in.mnemonic.rfind("push", 0) == 0) {
			stack_offset -= in.regs.size() * 4;
			continue;
		} else if (in.mnemonic.rfind("pop", 0) == 0) {
			stack_offset += in.regs.size() * 4;
			continue;
		}
	}

	for (auto succ : bb.successors) {
		stack_offset_forward_flow(*succ, stack_offset);
	}
	if (bb.is_exit()) {
		assert(stack_offset == 0);
	}
}

void stack_offset_analysis(basic_block& entry) {
	assert(entry.is_entry());
	stack_offset_forward_flow(entry, 0);
}
