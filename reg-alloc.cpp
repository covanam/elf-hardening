#include "cfg.h"
#include <cassert>
#include "reg-alloc.h"
#include <limits>

static constexpr int num_physical_reg = 8;

using register_interference_graph = std::map<vreg, std::set<vreg>>;

static void rig_forward_flow(
	basic_block& bb,
	register_interference_graph& rig
) {
	if (bb.visited)
		return;

	for (const auto& in : bb) {
		for (auto reg : in.live_regs) {
			if (rig.find(reg) == rig.end())
				rig.insert({reg, {}});

			rig[reg].insert(
				in.live_regs.begin(),
				in.live_regs.end()
			);
		}

		if (in.gen.size() > 1) {
			for (unsigned idx : in.gen) {
				if (rig.find(in.regs[idx]) == rig.end())
					rig.insert({in.regs[idx], {}});
				
				for (unsigned ii : in.gen)
					rig[in.regs[idx]].insert(in.regs[ii]);
			}
		}
	}

	bb.visited = true;

	for (basic_block* succ : bb.successors) {
		if (succ)
			rig_forward_flow(*succ, rig);
	}
}

register_interference_graph get_rig(
	control_flow_graph& cfg,
	basic_block& entry
) {
	register_interference_graph rig;

	cfg.reset();

	rig_forward_flow(entry, rig);

	rig.erase(vreg(0));
	rig.erase(vreg(1));
	rig.erase(vreg(2));
	rig.erase(vreg(3));
	rig.erase(vreg(12));
	rig.erase(vreg(13));
	rig.erase(vreg(14));
	rig.erase(vreg(15));
	for (auto& r : rig) {
		r.second.erase(vreg(0));
		r.second.erase(vreg(1));
		r.second.erase(vreg(2));
		r.second.erase(vreg(3));
		r.second.erase(vreg(12));
		r.second.erase(vreg(13));
		r.second.erase(vreg(14));
		r.second.erase(vreg(15));
	}

	return rig;
}

static int spill_forward_flow(basic_block& bb, vreg reg) {
	int cost = 0;
	if (bb.visited)
		return 0;

	for (const auto& in : bb) {
		for (vreg r : in.regs) {
			if (r == reg) {
				cost++;
				break;
			}
		}
	}

	bb.visited = true;

	for (basic_block* succ : bb.successors) {
		if (succ)
			cost += spill_forward_flow(*succ, reg);
	}

	return cost;
}

int spilling_cost(
	control_flow_graph& cfg,
	basic_block& entry,
	vreg reg
) {
	if (reg.num == 14) // don't spill LR
		return std::numeric_limits<int>::max();

	cfg.reset();

	return spill_forward_flow(entry, reg);
}



std::map<vreg, int> register_allocate(
	control_flow_graph& cfg,
	basic_block& entry
) {
	register_interference_graph rig = get_rig(cfg, entry);

	std::list<std::pair<vreg, std::set<vreg>>> stack;
	std::vector<vreg> spilled_regs;

	while (true) {
		register_interference_graph temp = rig;
		stack.clear();
		bool changed = true;
		while (changed) {
			changed = false;
			for (auto r = temp.begin(); r != temp.end();) {
				auto next = std::next(r);
				if (r->second.size() <= num_physical_reg) {
					stack.push_back({r->first, r->second});
					changed = true;
					vreg n = r->first;
					temp.erase(r);
					for (auto& rr : temp) {
						rr.second.erase(n);
					}
				}
				r = next;
			}
		}

		if (temp.size() != 0) {
			int min_cost = std::numeric_limits<int>::max();
			vreg spilled;
			for (const auto& r : temp) {
				int cost = spilling_cost(cfg, entry, r.first);
				if (cost < min_cost) {
					min_cost = cost;
					spilled = r.first;
				}
			}
			rig.erase(spilled);
			for (auto& r : rig) {
				r.second.erase(spilled);
			}
			spilled_regs.push_back(spilled);
		} else {
			break;
		}
	}

	std::map<vreg, int> allocation;

	for (vreg spilled : spilled_regs) {
		allocation.insert({spilled, -1});
	}

	rig.clear();

	for (auto r = stack.rbegin(); r != stack.rend(); r++) {
		rig.insert(*r);
		vreg n = r->first;
		for (auto& rr : rig) {
			rr.second.insert(n);
		}

		if (n.num != 14) {
			std::set<int> available = {4, 5, 6, 7, 8, 9, 10, 11};

			for (auto i : r->second) {
				auto allocated = allocation.find(i);
				if (allocated != allocation.end()) {
					available.erase(allocated->second);
				}
			}

			assert(available.begin() != available.end());
			allocation.insert({r->first, *available.begin()});
		}
		else {
			allocation.insert({r->first, 14});
		}
	}

	return allocation;
}
