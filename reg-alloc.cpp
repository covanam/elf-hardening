#include "cfg.h"
#include <cassert>
#include "reg-alloc.h"
#include <limits>
#include "analysis.h"

static constexpr int num_physical_reg = 11;

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
	}

	bb.visited = true;

	for (basic_block* succ : bb.successors) {
		rig_forward_flow(*succ, rig);
	}

	for (basic_block* pred : bb.predecessors) {
		rig_forward_flow(*pred, rig);
	}
}

static void get_unused_variables_interference(
	basic_block& bb,
	register_interference_graph& rig
) {
	if (bb.visited)
		return;
	
	bb.visited = true;

	for (auto in = bb.begin(); in != bb.end(); ++in) {
		for (auto reg : in->regs) {
			if (rig.find(reg) != rig.end())
				continue;

			std::set<vreg> overwritten;

			if (std::next(in) == bb.end()) {
				for (auto succ : bb.successors) {
					overwritten.insert(
						succ->front().live_regs.begin(),
						succ->front().live_regs.end());
				}
			} else {
				overwritten = std::next(in)->live_regs;
			}

			overwritten.insert(reg);

			for (vreg r : overwritten) {
				rig[r].insert(
					overwritten.begin(), overwritten.end());
			}
		}
	}

	for (basic_block* succ : bb.successors) {
		get_unused_variables_interference(*succ, rig);
	}

	for (basic_block* pred : bb.predecessors) {
		get_unused_variables_interference(*pred, rig);
	}
}

static void get_multiple_written_interference(
	basic_block& bb,
	register_interference_graph& rig
) {
	if (bb.visited)
		return;

	for (const auto& in : bb) {
		if (in.gen.size() > 1) {
			for (unsigned idx : in.gen) {
				assert(rig.find(in.regs[idx]) != rig.end());
				
				for (unsigned ii : in.gen)
					rig[in.regs[idx]].insert(in.regs[ii]);
			}
		}
	}

	bb.visited = true;

	for (basic_block* succ : bb.successors) {
		get_multiple_written_interference(*succ, rig);
	}

	for (basic_block* pred : bb.predecessors) {
		get_multiple_written_interference(*pred, rig);
	}
}

register_interference_graph get_rig(
	control_flow_graph& cfg,
	basic_block& entry
) {
	register_interference_graph rig;

	cfg.reset();

	rig_forward_flow(entry, rig);

	cfg.reset();
	get_unused_variables_interference(entry, rig);

	cfg.reset();
	get_multiple_written_interference(entry, rig);

	rig.erase(vreg(12));
	rig.erase(vreg(13));
	rig.erase(vreg(14));
	rig.erase(vreg(15));
	for (auto& r : rig) {
		r.second.erase(vreg(12));
		r.second.erase(vreg(13));
		r.second.erase(vreg(14));
		r.second.erase(vreg(15));
	}

	return rig;
}

static float usage_count_forward_flow(basic_block& bb, vreg reg) {
	float cost = 0;
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
		cost += usage_count_forward_flow(*succ, reg);
	}

	return cost;
}

float usage_count(
	control_flow_graph& cfg,
	basic_block& entry,
	vreg reg
) {
	if (reg.num < 4)
		return std::numeric_limits<float>::max();

	cfg.reset();

	return usage_count_forward_flow(entry, reg);
}

static bool done_removing(const register_interference_graph& rig) {
	for (const auto& r : rig) {
		if (r.first.num >= 16)
			return false;
	}
	return true;
}

std::map<vreg, vreg> register_allocate(
	control_flow_graph& cfg,
	basic_block& entry
) {
	register_interference_graph rig = get_rig(cfg, entry);

	std::list<std::pair<vreg, std::set<vreg>>> stack;
	std::list<std::pair<vreg, std::set<vreg>>> spilled_regs;

	auto r11 = rig.find(vreg(11));
	if (r11 != rig.end()) {
		spilled_regs.push_back(*r11);
		rig.erase(r11);
		for (auto& r : rig)
			r.second.erase(vreg(11));
	}

	while (true) {
		register_interference_graph temp = rig;
		stack.clear();
		bool changed = true;
		while (changed) {
			changed = false;
			for (auto r = temp.begin(); r != temp.end();) {
				auto next = std::next(r);
				if (r->first.num < 16) {
					// do nothing
				}
				else if (r->second.size() <= num_physical_reg) {
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

		if (!done_removing(temp)) {
			float min_cost = std::numeric_limits<float>::max();
			vreg spilled;
			for (const auto& r : temp) {
				float cost = usage_count(cfg, entry, r.first) / r.second.size();
				if (cost < min_cost) {
					min_cost = cost;
					spilled = r.first;
				}
			}
			spilled_regs.push_back({spilled, rig[spilled]});
			rig.erase(spilled);
			for (auto& r : rig) {
				r.second.erase(spilled);
			}
		} else {
			break;
		}
	}

	std::map<vreg, vreg> allocation;

	for (auto s = spilled_regs.rbegin(); s != spilled_regs.rend(); ++s) {
		int i = 0;
		bool conflict;

		do {
			conflict = false;
			for (auto r : s->second) {
				auto a = allocation.find(r);
				if (a == allocation.end())
					continue;
				
				if (a->second.spill_slot == i) {
					conflict = true;
					++i;
					break;
				}
			}
		} while (conflict);

		if (s->first.num < 16)
			allocation.insert({s->first, vreg::spill(i, s->first.num)});
		else
			allocation.insert({s->first, vreg::spill(i)});
	}

	for (auto r = stack.rbegin(); r != stack.rend(); r++) {
		if (true) {
			std::set<int> available = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
			for (auto i : r->second) {
				auto allocated = allocation.find(i);
				if (allocated != allocation.end()) {
					available.erase(allocated->second.num);
				}
				else if (i.num == r->first.num) {
					// pass
				}
				else {
					assert(i.num < 11);
					available.erase(i.num);
				}
			}
			assert(available.begin() != available.end());
			allocation.insert({r->first, vreg(*--available.end())});
		}
		else {
			allocation.insert({r->first, vreg(14)});
		}
	}

	return allocation;
}

static void look_use(
	vreg reg, basic_block& bb, basic_block::iterator start,
	std::set<vins*>& def_ins, std::set<vins*>& use_ins
);

static void look_def(
	vreg reg, basic_block& bb, basic_block::reverse_iterator start,
	std::set<vins*>& def_ins, std::set<vins*>& use_ins
) {
	for (auto it = start; it != bb.rend(); ++it) {
		auto& in = *it;

		if (def_ins.find(&in) != def_ins.end())
			return;

		for (unsigned i : in.gen) {
			if (in.regs[i] == reg) {
				def_ins.insert(&in);
				look_use(reg, bb, it.base(), def_ins, use_ins);

				if (in.cond.size())
					continue;

				// defined register is not also used?
				// then we are done here
				if (std::find(in.use.begin(), in.use.end(), i) == in.use.end())
					return;
			}
		}
	}

	for (auto pred : bb.predecessors) {
		if (!pred->backward_visited) {
			pred->backward_visited = true;
			look_def(reg, *pred, pred->rbegin(), def_ins, use_ins);
		}
	}
}

static void look_use(
	vreg reg, basic_block& bb, basic_block::iterator start,
	std::set<vins*>& def_ins, std::set<vins*>& use_ins
) {
	for (auto it = start; it != bb.end(); ++it) {
		auto& in = *it;

		if (use_ins.find(&in) != use_ins.end())
			return;

		for (unsigned i : in.use) {
			if (in.regs[i] == reg) {
				use_ins.insert(&in);
				look_def(reg, bb, std::reverse_iterator(it),
				         def_ins, use_ins);
			}
		}

		for (unsigned i : in.gen) {
			if (in.regs[i] == reg) {
				if (in.cond.size())
					continue;
				auto tmp = std::find(in.use.begin(), in.use.end(), i);
				if (tmp != in.use.end()) {
					continue;
				} else {
					return;
				}
			}
		}
	}

	for (auto succ : bb.successors) {
		if (!succ->forward_visited) {
			succ->forward_visited = true;
			look_use(reg, *succ, succ->begin(), def_ins, use_ins);
		}
	}
}

static void rename(vreg from, vreg to, std::set<vins*>& def, std::set<vins*>& use) {
	for (vins* in : use) {
		for (unsigned i : in->use) {
			if (in->regs[i] == from) {
				in->regs[i] = to;
			}
		}
	}

	for (vins* in : def) {
		for (unsigned i : in->gen) {
			if (in->regs[i] == from) {
				in->regs[i] = to;
			}
		}
	}
}

static bool need_virtualized(vreg reg) {
	// anything between r0-r11
	// #TODO: r14(lr) and r12(ip) can be used too
	return reg >= vreg(0) && reg <= vreg(11) || reg.num >= 16 && reg.num < 32;
}

static basic_block& find_bb_containing_vins(
	control_flow_graph &cfg,
	vins* in
) {
	for (auto& bb : cfg) {
		for (auto& i : bb) {
			if (&i == in)
				return bb;
		}
	}

	assert(0);
}

void split_registers(control_flow_graph& cfg) {
	vreg v(32);

	for (auto& bb : cfg) {
		if (bb.front().is_pseudo() && bb.front().operands == "func_entry") {
			for (vreg r : bb.begin()->regs) {
				if (r.num < 0) continue;
				cfg.reset();
				std::set<vins*> use_ins, def_ins;
				look_def(r, bb, std::prev(bb.rend()),
					def_ins, use_ins);

				rename(r, vreg::spill(r.num), def_ins, use_ins);
			}
		}
	}

	for (auto& bb : cfg) {
		if (bb.front().is_data())
			continue;

		if (bb.rbegin()->is_pseudo() && bb.rbegin()->operands == "func_exit") {
			for (vreg r : bb.rbegin()->regs) {
				if (r.num < 0) continue;
				cfg.reset();
				std::set<vins*> use_ins, def_ins;
				look_use(r, bb, std::prev(bb.end()), def_ins, use_ins);
				rename(r, vreg::spill(r.num), def_ins, use_ins);
			}
		}

		for (auto it = bb.begin(); it != bb.end(); ++it) {
			if (it->is_call() && !it->is_local_call()) {
				for (unsigned i : it->use) {
					vreg r = it->regs[i];
					if (r.num < 0) continue;
					cfg.reset();
					std::set<vins*> use_ins, def_ins;
					look_use(r, bb, it, def_ins, use_ins);
					rename(r, vreg::spill(r.num), def_ins, use_ins);
				}
			}
		}

		for (auto it = bb.rbegin(); it != bb.rend(); ++it) {
			if (it->is_call() && !it->is_local_call()) {
				for (unsigned i : it->gen) {
					vreg r = it->regs[i];
					if (r.num < 0) continue;
					cfg.reset();
					std::set<vins*> use_ins, def_ins;
					look_def(r, bb, it, def_ins, use_ins);
					rename(r, vreg::spill(r.num), def_ins, use_ins);
				}
			}
		}

		for (auto it = bb.begin(); it != bb.end(); ++it) {
			if (it->mnemonic.rfind("stm", 0) == 0 ||
			    it->mnemonic.rfind("push", 0) == 0
			) {
				for (unsigned i : it->use) {
					vreg r = it->regs[i];
					if (r.num < 0) continue;
					cfg.reset();
					std::set<vins*> use_ins, def_ins;
					look_use(r, bb, it, def_ins, use_ins);
					rename(r, vreg::spill(r.num), def_ins, use_ins);
				}
			}
		}

		for (auto it = bb.rbegin(); it != bb.rend(); ++it) {
			if (it->mnemonic.rfind("ldm", 0) == 0 ||
			    it->mnemonic.rfind("pop", 0) == 0
			) {
				for (unsigned i : it->gen) {
					vreg r = it->regs[i];
					if (r.num < 0) continue;
					cfg.reset();
					std::set<vins*> use_ins, def_ins;
					look_def(r, bb, it, def_ins, use_ins);
					rename(r, vreg::spill(r.num), def_ins, use_ins);
				}
			}
		}
	}

	for (auto& bb : cfg) {
		if (bb.front().is_data())
			continue;

		for (auto it = bb.begin(); it != bb.end(); ++it) {
			for (unsigned i : it->use) {
				vreg reg = it->regs[i];
				if (need_virtualized(reg)) {
					cfg.reset();
					std::set<vins*> use_ins, def_ins;
					cfg.reset();
					look_use(reg, bb, it,
				                 def_ins, use_ins);
					rename(reg, v, def_ins, use_ins);
					v.num++;
				}
			}
		}

		for (auto it = bb.rbegin(); it != bb.rend(); ++it) {
			for (unsigned i : it->gen) {
				vreg reg = it->regs[i];
				if (need_virtualized(reg)) {
					cfg.reset();
					std::set<vins*> use_ins, def_ins;
					cfg.reset();
					look_def(reg, bb, it,
				                 def_ins, use_ins);
					rename(reg, v, def_ins, use_ins);
					v.num++;
				}
			}
		}
	}

	for (auto& bb : cfg) {
		for (auto& in : bb) {
			for (vreg& r : in.regs) {
				if (r.spill_slot >= 0)
					r = vreg(r.spill_slot);
			}
		}
	}
}

static std::vector<vreg> find_free_reg(const vins& in) {
	std::vector<vreg> free_reg;
	for (int i = 0; i < 11; ++i) {
		auto tmp = in.live_regs.find(vreg(i));
		if (tmp == in.live_regs.end())
			free_reg.push_back(vreg(i));
	}
	return free_reg;
}

static int get_needed_stack(basic_block& bb, int current) {
	if (bb.visited)
		return current;
	
	bb.visited = true;

	for (const auto& in : bb) {
		for (const auto reg : in.regs) {
			if (4 * reg.spill_slot + 4 > current)
				current = 4 * reg.spill_slot + 4;
		}
	}

	for (const auto succ : bb.successors) {
		int n = get_needed_stack(*succ, current);
		if (n > current)
			current = n;
	}

	for (const auto pred : bb.predecessors) {
		int n = get_needed_stack(*pred, current);
		if (n > current)
			current = n;
	}

	return current;
}

control_flow_graph::iterator bb_to_iter(control_flow_graph& cfg, basic_block& bb) {
	for (auto iter = cfg.begin(); iter != cfg.end(); ++iter) {
		if (&*iter == &bb)
			return iter;
	}
	assert(0);
}

static void insert_stack_recover(
	control_flow_graph& cfg,
	basic_block& bb,
	int s
) {
	if (bb.visited)
		return;
	bb.visited = true;

	if (bb.back().is_pseudo() && bb.back().operands == "func_exit") {
		auto ret = std::prev(bb.end(), 2);
		assert(ret->is_function_return());

		for (vreg& r : ret->regs) {
			if (r.num == 15) { // pc
				r.num = 14; // lr

				vins tmp = vins::ins_return();
				bb.insert(std::prev(bb.end()), std::move(tmp));
			}
		}

		ret = std::prev(bb.end(), 2);

		basic_block store_second_stack = basic_block({
			vins::ins_ldr(vreg(12), ".second_stack"), // address of stack ptr
			vins::ins_sub(vreg(11), vreg(11), s + 4), // subtract stack ptr
			vins::ins_str(vreg(11), vreg(12), 0), // save stack ptr
			vins::ins_ldr(vreg(11), vreg(11), 0), // recover original r11
		});
		ret->transfer_label(store_second_stack.front());
		bb.splice(std::prev(bb.end(), 2), store_second_stack);

		for (auto& succ : bb.successors) {
			basic_block load_second_stack = basic_block({
				vins::ins_ldr(vreg(12), ".second_stack"),
				vins::ins_ldr(vreg(12), vreg(12), 0),
				vins::ins_str(vreg(11), vreg(12), 0),
				vins::ins_add(vreg(11), vreg(12), s + 4),
				vins::ins_ldr(vreg(12), ".second_stack"),
				vins::ins_str(vreg(11), vreg(12), 0)
			});
			auto iter = bb_to_iter(cfg, *succ);
			load_second_stack.predecessors.push_back(&bb);
			load_second_stack.successors.push_back(&*iter);
			cfg.insert(iter, std::move(load_second_stack));
			succ = &*std::prev(iter);
			for (auto& p : iter->predecessors) {
				if (p == &bb) {
					p = succ;
					break;
				}
			}
		}
	}
	{
		for (auto succ : bb.successors) {
			insert_stack_recover(cfg, *succ, s);
		}
	}
}

static void fix_stack_reference(vins& in, int v) {
	if (in.mnemonic.rfind("ldr", 0) == 0 ||
	    in.mnemonic.rfind("str", 0) == 0) {
		for (unsigned i : in.use) {
			if (in.regs[i].num == 13) {
				int bra_p = in.operands.find(']');
				int off_p = in.operands.find("%i");

				assert(bra_p != std::string::npos);
				assert(off_p < bra_p);

				if(off_p == std::string::npos)
					in.operands.insert(bra_p, ", %i");

				in.imm() += v;
			}
		}
	}
}

void spill(control_flow_graph& cfg) {
	for (auto& bb : cfg) {
		for (auto& in : bb) {
			in.live_regs.clear();
		}
	}

	std::map<basic_block*, int> stack_reserve;

	cfg.reset();

	for (auto& bb : cfg) {
		if (bb.front().is_pseudo() && bb.front().operands == "func_entry") {
			cfg.reset();
			int s = get_needed_stack(bb, 0);
			stack_reserve.insert({&bb, s});
		}
	}

	for (auto& bb : cfg) {
		for (auto in = bb.begin(); in != bb.end(); ++in) {
			std::vector<vreg> regs;
			std::vector<vreg> use_regs;
			std::vector<vreg> def_regs;
			for (unsigned i : in->use) {
				if (in->regs[i].spill_slot >= 0 && in->regs[i].num >= 0) {
					use_regs.push_back(in->regs[i]);
					regs.push_back(vreg(in->regs[i].num));
					in->regs[i] = vreg(in->regs[i].num);
				}
			}
			for (unsigned i : in->gen) {
				if (in->regs[i].spill_slot >= 0 && in->regs[i].num >= 0) {
					def_regs.push_back(in->regs[i]);
					regs.push_back(vreg(in->regs[i].num));
					in->regs[i] = vreg(in->regs[i].num);
				}
			}

			if (regs.empty())
				continue;

			if (in->is_pseudo() && in->operands == "func_entry") {
				assert(use_regs.empty());
				auto pos = std::next(in);
				for (vreg r : def_regs) {
					if (r.num == 11)
						continue;
					vins tmp = vins::ins_str(vreg(r.num), vreg(11), -4 - 4 * r.spill_slot);
					bb.insert(pos, std::move(tmp));
				}
			}
			else if (in->is_pseudo() && in->operands == "func_exit") {
				assert(def_regs.empty());
				auto pos = std::prev(in);
				for (auto& ngu : bb) {
				}

				for (vreg& r : pos->regs) {
					if (r.num == 15) { // pc
						r.num = 14; // lr

						vins tmp = vins::ins_return();
						bb.insert(std::prev(bb.end()), std::move(tmp));
					}
				}

				pos = std::prev(bb.end(), 2);

				assert(pos->is_function_return());
				for (vreg r : use_regs) {
					if (r.num == 11)
						continue;
					vins tmp = vins::ins_ldr(vreg(r.num), vreg(11), -4 - 4 * r.spill_slot);
					pos->transfer_label(tmp);
					bb.insert(pos, std::move(tmp));
				}
			}
			else {

				if (in->mnemonic.rfind("pop", 0) == 0) {
					for (vreg& r : in->regs) {
						if (r.num == 15) { // pc
							r.num = 14; // lr

							vins tmp = vins::ins_return();
							bb.insert(std::next(in), std::move(tmp));
						}
					}
				}

				bool use_r11 = false;
				for (vreg r : in->regs) {
					if (r.num == 11)
						use_r11 = true;
				}

				if (use_r11) {
					vreg stack_ptr = vreg(0);
					while (true) {
						bool changed = false;
						for (vreg r : in->regs) {
							if (r.num == stack_ptr.num)
								changed = true; 
								stack_ptr.num++;
								break;
						}
						if (!changed)
							break;
					}
					assert(stack_ptr.num < 11);

					vins tmp;

					tmp = vins::push_second_stack<std::initializer_list<vreg>>({stack_ptr});
					in->transfer_label(tmp);
					bb.insert(in, std::move(tmp));

					tmp = vins::ins_mov(stack_ptr, vreg(11));
					bb.insert(in, std::move(tmp));

					tmp = vins::stmia(stack_ptr, regs);
					bb.insert(in, std::move(tmp));

					for (vreg r : use_regs) {
						tmp = vins::ins_ldr(vreg(r.num), stack_ptr, -8 - 4 * (r.spill_slot + regs.size()));
						bb.insert(in, std::move(tmp));
					}

					auto pos = std::next(in);
					for (vreg r : def_regs) {
						tmp = vins::ins_str(vreg(r.num), stack_ptr, -8 - 4 * (r.spill_slot + regs.size()));
						bb.insert(pos, std::move(tmp));
					}

					tmp = vins::ldmdb(stack_ptr, regs);
					bb.insert(pos, std::move(tmp));

					tmp = vins::ins_mov(vreg(11), stack_ptr);
					bb.insert(pos, std::move(tmp));

					tmp = vins::pop_second_stack<std::initializer_list<vreg>>({stack_ptr});
					bb.insert(pos, std::move(tmp));
				}
				else {

				vins tmp;
				if (regs.size()) {
					tmp = vins::push_second_stack(regs);
					in->transfer_label(tmp);
					bb.insert(in, std::move(tmp));
				}
				for (vreg r : use_regs) {
					tmp = vins::ins_ldr(vreg(r.num), vreg(11), -4 - 4 * (r.spill_slot + regs.size()));
					bb.insert(in, std::move(tmp));
				}
				auto pos = std::next(in);
				for (vreg r : def_regs) {
					tmp = vins::ins_str(vreg(r.num), vreg(11), -4 - 4 * (r.spill_slot + regs.size()));
					bb.insert(pos, std::move(tmp));
				}
				if (regs.size()) {
					tmp = vins::pop_second_stack(regs);
					bb.insert(pos, std::move(tmp));
				}
				}
			}
		}
	}

	cfg.reset();
	liveness_analysis(cfg);

	cfg.reset();

	for (auto& bb : cfg) {
		if (bb.front().is_pseudo() && bb.front().operands == "func_entry") {
			int s = stack_reserve.at(&bb);
			if (s == 0) continue;

			basic_block load_second_stack = basic_block({
				vins::ins_ldr(vreg(12), ".second_stack"),
				vins::ins_ldr(vreg(12), vreg(12), 0),
				vins::ins_str(vreg(11), vreg(12), 0),
				vins::ins_add(vreg(11), vreg(12), s + 4),
				vins::ins_ldr(vreg(12), ".second_stack"),
				vins::ins_str(vreg(11), vreg(12), 0)
			});

			bb.splice(std::next(bb.begin()), load_second_stack);

			insert_stack_recover(cfg, bb, s);
		}
	}


	for (auto& bb : cfg) {
		for (auto in = bb.begin(); in != bb.end(); ++in) {
			auto next = std::next(in);

			std::map<int, int> reg_map;

			for (vreg r : in->regs) {
				if (r.spill_slot >= 0)
					reg_map.insert({r.spill_slot, -1});
			}

			if (reg_map.size() == 0)
				continue;
			
			std::vector<vreg> free_regs = find_free_reg(*in);

			int need = reg_map.size() - free_regs.size();
			std::vector<vreg> to_stack;

			if (need > 0) {
				auto l = in->live_regs.begin();
				for (int i = 0; i < need; ++i) {
					while (l != in->live_regs.end() &&
					       !(0 <= l->num && l->num < 11) ||
					       std::find(in->regs.begin(), in->regs.end(), *l)
					         != in->regs.end()
					       ) {
						++l;
					}
					if (l == in->live_regs.end())
						break;
					
					to_stack.push_back(*l);
					++l;
				}
				
				vins push_ins = vins::push_second_stack(to_stack);
				in->transfer_label(push_ins);
				bb.insert(in, std::move(push_ins));
				bb.insert(std::next(in), vins::pop_second_stack(to_stack));
				free_regs.insert(free_regs.end(), to_stack.begin(), to_stack.end());
			}

			assert(free_regs.size() >= reg_map.size());

			int free_regs_idx = 0;
			for (auto& m : reg_map) {
				m.second = free_regs[free_regs_idx].num;
				free_regs_idx++;
			}

			for (unsigned i : in->use) {
				if (in->regs[i].spill_slot >= 0) {
					vreg r = vreg(reg_map.at(in->regs[i].spill_slot));
					vins tmp = vins::ins_ldr(r, vreg(11), - 4 - 4 * (in->regs[i].spill_slot + to_stack.size()));
					in->transfer_label(tmp);
					bb.insert(in, std::move(tmp));
				}
			}

			for (unsigned i : in->gen) {
				if (in->is_jump()) {
					if (in->mnemonic.rfind("pop", 0) == 0) {
						for (vreg& r : in->regs) {
							if (r.num == 15) { // pc
								r.num = 14; // lr

								vins tmp = vins::ins_return();
								bb.insert(std::next(in), std::move(tmp));
							}
						}
					}
				}
				if (in->regs[i].spill_slot >= 0) {
					vreg r = vreg(reg_map.at(in->regs[i].spill_slot));
					vins tmp = vins::ins_str(r, vreg(11), -4 - 4 * (in->regs[i].spill_slot + to_stack.size()));
					bb.insert(std::next(in), std::move(tmp));
				}
			}

			for (vreg& r : in->regs) {
				if (r.spill_slot >= 0) {
					r = vreg(reg_map.at(r.spill_slot));
				}
			}
		}
	}
}

static void apply_allocate(basic_block& bb, std::map<vreg, int>& replace_map) {
	if (bb.visited)
		return;
	
	bb.visited = true;

	for (vins& in : bb) {
		for (vreg& reg : in.regs) {
			auto f = replace_map.find(reg);
			if (f != replace_map.end()) {
				reg.num = f->second;
			}
		}
	}

	for (basic_block* succ : bb.successors) {
		apply_allocate(*succ, replace_map);
	}

	for (basic_block* pred : bb.predecessors) {
		apply_allocate(*pred, replace_map);
	}
}
