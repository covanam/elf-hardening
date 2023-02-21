#include "cfg.h"
#include "disasm.h"
#include <set>
#include <cassert>
#include "liveness.h"

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
	for (auto bb = cfg.rbegin(); bb != cfg.rend(); ++bb) {
		if (bb->front().is_data())
			continue;

		if (bb->is_returning())
			reverse_flow(*bb, use_at_func_return);
	}
}
