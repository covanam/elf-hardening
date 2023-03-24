#include "cfg.h"
#include <cassert>
#include "reg-alloc.h"
#include <limits>
#include "analysis.h"

static constexpr int num_physical_reg = 12;

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
		rig_forward_flow(*succ, rig);
	}

	for (basic_block* pred : bb.predecessors) {
		rig_forward_flow(*pred, rig);
	}
}

register_interference_graph get_rig(
	control_flow_graph& cfg,
	basic_block& entry
) {
	register_interference_graph rig;

	cfg.reset();

	rig_forward_flow(entry, rig);

	for (auto& bb : cfg) {
		/* #TODO: not the entire CFG! */
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

				rig.insert({reg, overwritten});
			}
		}
	}

	std::cout << "Rig:\n";
	for (auto& r : rig) {
		std::cout << r.first << " -- (";
		for (auto reg : r.second)
			std::cout << reg << ' ';
		std::cout << ")\n";
	}

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
		cost += spill_forward_flow(*succ, reg);
	}

	return cost;
}

int spilling_cost(
	control_flow_graph& cfg,
	basic_block& entry,
	vreg reg
) {
	if (reg.num < 16)
		return std::numeric_limits<int>::max();

	cfg.reset();

	return spill_forward_flow(entry, reg);
}

static bool done_removing(const register_interference_graph& rig) {
	for (const auto& r : rig) {
		if (r.first.num >= 16)
			return false;
	}
	return true;
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

	int i = -1;
	for (vreg spilled : spilled_regs) {
		allocation.insert({spilled, i});
		--i;
	}

	for (auto r = stack.rbegin(); r != stack.rend(); r++) {
		if (true) {
			std::set<int> available = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
			std::cout << "interfere: ("; for (auto ngu : r->second) std::cout << ngu << ' '; std::cout << ")\n";
			for (auto i : r->second) {
				auto allocated = allocation.find(i);
				if (allocated != allocation.end()) {
					available.erase(allocated->second);
				}
				else if (i.num == r->first.num) {
					// pass
				}
				else {
					assert(i.num < 12);
					available.erase(i.num);
				}
			}
			std::cout << std::flush;
			assert(available.begin() != available.end());
			allocation.insert({r->first, *--available.end()});
			std::cout << "Thus allocate: " << r->first << " to " << *--available.end() << "\n\n";
		}
		else {
			allocation.insert({r->first, 14});
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

		//std::cout << "Look for def " << reg << " from: " << in << '\n';

		if (def_ins.find(&in) != def_ins.end())
			return;

		for (unsigned i : in.gen) {
			if (in.regs[i] == reg) {
				def_ins.insert(&in);
				//std::cout << "\tFound def!\n";
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

		//std::cout << "Look for use "<< reg <<" from: " << in << '\n';

		if (use_ins.find(&in) != use_ins.end())
			return;

		for (unsigned i : in.use) {
			if (in.regs[i] == reg) {
				use_ins.insert(&in);
				//std::cout << "\tFound use!\n";
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
		std::cout << "Rename use: " << *in << " (";
		for (vreg r : in->regs) {
			std::cout << r << ' ';
		}
		std::cout << ") -> ";
		for (unsigned i : in->use) {
			if (in->regs[i] == from) {
				in->regs[i] = to;
			}
		}
		std::cout << "(";
		for (vreg r : in->regs) {
			std::cout << r << ' ';
		}
		std::cout << ")\n";
	}

	for (vins* in : def) {
		std::cout << "Rename use: " << *in << " (";
		for (vreg r : in->regs) {
			std::cout << r << ' ';
		}
		std::cout << ") -> ";
		for (unsigned i : in->gen) {
			if (in->regs[i] == from) {
				in->regs[i] = to;
			}
		}
		std::cout << "(";
		for (vreg r : in->regs) {
			std::cout << r << ' ';
		}
		std::cout << ")\n";
	}
}

static bool need_virtualized(vreg reg) {
	// anything between r0-r11
	// #TODO: r14(lr) and r12(ip) can be used too
	return reg >= vreg(0) && reg <= vreg(11) || reg >= 16 && reg < 32;
}

void split_registers(control_flow_graph& cfg, const std::string& entry) {
	vreg v(32);

	control_flow_graph::iterator entry_iter;
	for (entry_iter = cfg.begin(); entry_iter != cfg.end(); ++entry_iter) {
		if (entry_iter->begin()->label == entry) {
			for (vreg r : entry_iter->begin()->regs) {
				if (r.num < 0) continue;
				cfg.reset();
				std::set<vins*> use_ins, def_ins;
				look_use(r, *entry_iter, std::next(entry_iter->begin()),
					def_ins, use_ins);
				rename(r, -r.num - 1, def_ins, use_ins);
			}
			break;
		}
	}

	assert(entry_iter != cfg.end());

	for (auto it = entry_iter;; ++it) {
		basic_block& bb = *it;
		if (bb.rbegin()->is_pseudo() && bb.rbegin()->operands == "func_exit") {
			//std::cout << "func_exit " << bb.rbegin()->label << '\n';
			for (vreg r : bb.rbegin()->regs) {
				if (r.num < 0) continue;
				cfg.reset();
				std::set<vins*> use_ins, def_ins;
				look_def(r, bb, bb.rbegin(), def_ins, use_ins);
				rename(r, -r.num - 1, def_ins, use_ins);
			}
		}

		for (auto it = bb.begin(); it != bb.end(); ++it) {
			if (it->is_call()) {
				for (unsigned i : it->use) {
					vreg r = it->regs[i];
					if (r.num < 0) continue;
					cfg.reset();
					std::set<vins*> use_ins, def_ins;
					look_use(r, bb, it, def_ins, use_ins);
					rename(r, -r.num - 1, def_ins, use_ins);
				}

				for (unsigned i : it->gen) {
					vreg r = it->regs[i];
					if (r.num < 0) continue;
					cfg.reset();
					std::set<vins*> use_ins, def_ins;
					def_ins.insert(&*it);
					look_use(r, bb, std::next(it), def_ins, use_ins);
					rename(r, -r.num - 1, def_ins, use_ins);
				}
			}
		}

		for (auto it = bb.begin(); it != bb.end(); ++it) {
			if (it->mnemonic.rfind("stm", 0) == 0) {
				for (unsigned i : it->use) {
					vreg r = it->regs[i];
					if (r.num < 0) continue;
					cfg.reset();
					std::set<vins*> use_ins, def_ins;
					look_use(r, bb, it, def_ins, use_ins);
					rename(r, -r.num - 1, def_ins, use_ins);
				}
			}
		}

		for (auto it = bb.rbegin(); it != bb.rend(); ++it) {
			if (it->mnemonic.rfind("ldm", 0) == 0) {
				for (unsigned i : it->gen) {
					vreg r = it->regs[i];
					if (r.num < 0) continue;
					cfg.reset();
					std::set<vins*> use_ins, def_ins;
					look_def(r, bb, it, def_ins, use_ins);
					rename(r, -r.num - 1, def_ins, use_ins);
				}
			}
		}

		if (std::next(it) == cfg.end())
			break;

		if (std::next(it)->front().is_data())
			break;
		
		if (std::next(it)->front().is_pseudo() &&
			std::next(it)->front().operands == "func_entry")
			break;
	}

	std::cout << "hello-:\n";
	for (auto& bb : cfg) {
		for (auto& in : bb) {
			std::cout << in << " (";
			for (vreg r : in.regs) {
				std::cout << r << ' ';
			}
			std::cout << ")\n";
		}
	}

	for (auto it = entry_iter;; ++it) {
		basic_block& bb = *it;
		for (auto it = bb.begin(); it != bb.end(); ++it) {
			for (unsigned i : it->use) {
				vreg reg = it->regs[i];
				if (need_virtualized(reg)) {
					cfg.reset();
					std::set<vins*> use_ins, def_ins;
					use_ins.insert(&*it);
					cfg.reset();
					look_def(reg, bb, std::reverse_iterator(it),
				                 def_ins, use_ins);
					rename(reg, v, def_ins, use_ins);
					v.num++;
				}
			}

			for (unsigned i : it->gen) {
				vreg reg = it->regs[i];
				if (need_virtualized(reg)) {
					cfg.reset();
					std::set<vins*> use_ins, def_ins;
					def_ins.insert(&*it);
					cfg.reset();
					look_use(reg, bb, std::next(it),
				                 def_ins, use_ins);
					rename(reg, v, def_ins, use_ins);
					v.num++;
				}
			}
		}

		if (std::next(it) == cfg.end())
			break;

		if (std::next(it)->front().is_data())
			break;
		
		if (std::next(it)->front().is_pseudo() &&
			std::next(it)->front().operands == "func_entry")
			break;
	}

	for (auto it = entry_iter; it != cfg.end(); ++it) {
		basic_block& bb = *it;
		for (auto& in : bb) {
			for (vreg& r : in.regs) {
				if (r.num < 0)
					r.num = -r.num - 1;
			}
		}
	}
}

static std::vector<vreg> find_free_reg(const vins& in) {
	std::vector<vreg> free_reg;
	for (int i = 0; i < 12; ++i) {
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
			if (-4 * reg.num > current)
				current = -4 * reg.num;
		}
	}

	for (const auto succ : bb.successors) {
		int n = get_needed_stack(*succ, current);
		if (n > current)
			current = n;
	}

	return current;
}

static void insert_stack_recover(basic_block& bb, int s) {
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

		vins tmp = vins::ins_add(vreg(13), vreg(13), s);
		bb.insert(std::prev(bb.end(), 2), std::move(tmp));

		return;
	} else {
		for (auto succ : bb.successors) {
			insert_stack_recover(*succ, s);
		}
	}
}

static void fix_stack_references(basic_block& bb, int v) {
	if (bb.visited)
		return;
	bb.visited = true;

	for (vins& in : bb) {
		if (in.mnemonic.rfind("ldr", 0) == 0) {
			for (unsigned i : in.use) {
				if (in.regs[i].num == 13) {
					if (in.imm() + in.stack_offset >= 0) {
						in.imm() += v;
					}
				}
			}
		}
	}

	for (auto succ : bb.successors) {
		fix_stack_references(*succ, v);
	}
}

void spill(control_flow_graph& cfg) {
	for (auto& bb : cfg) {
		for (auto& in : bb) {
			in.live_regs.clear();
		}
	}

	cfg.reset();

	liveness_analysis(cfg);

	std::cout << "\nLiveness after alloc:------------------------------------------\n";
	for (auto& bb : cfg) {
		for (auto& in : bb) {
			std::cout << in << "\t(";
			for (vreg r : in.live_regs) {
				std::cout << r << ' ';
			}
			std::cout << ")\n";
		}
	}

	std::map<basic_block*, int> stack_reserve;

	cfg.reset();

	for (auto& bb : cfg) {
		if (bb.front().is_pseudo() && bb.front().operands == "func_entry") {
			try {
				cfg.reset();
				stack_offset_analysis(bb);
			} catch (stack_analysis_failure& e) {
				std::cerr << "Failed to analyse stack. Reason:" << e.reason() << '\n';
				std::terminate();
			}

			cfg.reset();
			int s = get_needed_stack(bb, 0);
			stack_reserve.insert({&bb, s});
		}
	}

	std::cout << "Stack analysis:-------------------------------------------\n";
	for (auto& bb : cfg) {
		for (auto& in : bb) {
			std::cout << in << "\tstack = " << in.stack_offset << '\n';
		}
	}

	cfg.reset();

	for (auto& bb : cfg) {
		if (bb.front().is_pseudo() && bb.front().operands == "func_entry") {
			int s = stack_reserve.at(&bb);
			if (s == 0) continue;

			vins tmp = vins::ins_sub(vreg(13), vreg(13), s);
			std::next(bb.begin())->transfer_label(tmp);
			bb.insert(std::next(bb.begin()), std::move(tmp));

			cfg.reset();
			insert_stack_recover(bb, s);
			cfg.reset();
			fix_stack_references(bb, s);
		}
	}


	for (auto& bb : cfg) {
		for (auto in = bb.begin(); in != bb.end(); ++in) {
			auto next = std::next(in);

			std::map<int, int> reg_map;

			for (vreg r : in->regs) {
				if (r.num < 0)
					reg_map.insert({r.num, -1});
			}

			if (reg_map.size() == 0)
				continue;
			
			std::vector<vreg> free_regs = find_free_reg(*in);
			
			std::cout << "Spilling " << *in << '\n';

			int need = reg_map.size() - free_regs.size();
			std::vector<vreg> to_stack;

			if (need > 0) {
				auto l = in->live_regs.begin();
				for (int i = 0; i < need; ++i) {
					while (l != in->live_regs.end() &&
					       !(0 <= l->num && l->num < 12)) {
						++l;
					}
					if (l == in->live_regs.end())
						break;
					
					to_stack.push_back(*l);
					++l;
				}
				
				vins push_ins = vins::push(to_stack);
				in->transfer_label(push_ins);
				bb.insert(in, std::move(push_ins));
				bb.insert(std::next(in), vins::pop(to_stack));
				free_regs.insert(free_regs.end(), to_stack.begin(), to_stack.end());
			}

			assert(free_regs.size() >= reg_map.size());

			int free_regs_idx = 0;
			for (auto& m : reg_map) {
				m.second = free_regs[free_regs_idx].num;
				free_regs_idx++;
			}

			int stack_offset = in->stack_offset - 4 * to_stack.size();

			std::cout << "Orig_off = " << in->stack_offset << '\n'
				<< "New_off = " << stack_offset << '\n';

			for (unsigned i : in->use) {
				if (in->regs[i] < 0) {
					vreg r = reg_map.at(in->regs[i].num);
					std::cout  << "in->regs[i].num = " << in->regs[i].num << '\n';
					vins tmp = vins::ins_ldr(r, 13, -stack_offset - 4 * in->regs[i].num - 4);
					std::cout << "Stack loc: " << (-stack_offset - 4 * in->regs[i].num - 4) << '\n';
					in->regs[i] = r;
					in->transfer_label(tmp);
					bb.insert(in, std::move(tmp));
				}
			}

			stack_offset = in->stack_offset - 4 * to_stack.size();

			for (unsigned i : in->gen) {
				if (in->regs[i] < 0) {
					vreg r = reg_map.at(in->regs[i].num);
					vins tmp = vins::ins_str(r, 13, -stack_offset - 4 * in->regs[i].num - 4);
					std::cout  << "in->regs[i].num = " << in->regs[i].num << '\n';
					std::cout << "Stack loc: " << (-stack_offset - 4 * in->regs[i].num - 4) << '\n';
					in->regs[i] = r;
					bb.insert(std::next(in), std::move(tmp));
				}
			}
		}
	}
}

static void apply_allocate(basic_block& bb, std::map<vreg, int>& replace_map) {
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
