/*
TODO:
3.2 Eliminating the Memory Penalty (DONE)
3.3 Control Flow Checking (DONE)
3.4 Enhanced Control Flow Checking (DONE)
3.5.1 Control Flow Checking at Blocks with Stores (DONE)
3.5.2 Redundancy in Branch/Control Flow Checking (DONE)
4.1 Function calls (DONE)
*/

#include "reg-alloc.h"
#include "cfg.h"
#include <map>
#include "disasm.h"
#include <cassert>
#include "analysis.h"
#include <random>

static const vreg r_preserve_flags = vreg(31);
static const vreg r_duplicated_flags = vreg(32);
static const vreg r_rts = vreg(33);
static const vreg r_gsr = vreg(34);

static vreg new_ret_sig(){
	static vreg ret_sig(35);
	auto to_return = ret_sig;
	ret_sig.num++;
	assert(to_return.num < 64);
	return to_return;
}

static void duplicate_registers(control_flow_graph& cfg) {
	cfg.reset();
	liveness_analysis(cfg);

	for (auto& bb : cfg) {
		if (bb.front().is_pseudo() && bb.front().operands == "func_entry") {
			basic_block dup;

			for (vreg reg : bb.begin()->live_regs) {
				if (reg.num >= 16 && reg.num <= 30) {
					dup.push_back(vins::ins_mov(reg, vreg(reg.num - 16)));
				}
			}

			bb.splice(std::next(bb.begin()), dup);
		}
	}

	for (auto& bb : cfg) {
		for (auto& in : bb) {
			in.live_regs.clear();
		}
	}
}

static bool is_sync_point(const vins& in) {
	if (in.mnemonic.rfind("str", 0) == 0)
		return true;
	if (in.mnemonic.rfind("stm", 0) == 0)
		return true;
	if (in.is_jump())
		return true;
	
	return false;
}

static vreg duplicate(vreg r) {
	if (r.num < 15)
		return vreg(r.num + 16);
	if (r.num == 15)
		return r;
	assert(0);
}

static basic_block duplicate(lifter& lift, vins* in) {
	basic_block ins;

	{
		if (in->is_pseudo())
			return {};

		std::string cond = in->cond;

		vins dup = lift.duplicate(*in);
		dup.label.clear();

		for (vreg& r : dup.regs) {
			r = duplicate(r);
		}

		if (dup.mnemonic.rfind("push", 0) == 0) {
			// #TODO should we push twice?
			ins.push_back(vins::ins_sub(vreg(29), vreg(29), 4 * in->regs.size()));
			ins.back().cond = cond;
			ins.back().mnemonic.append(cond);
		}
		else if (dup.mnemonic.rfind("pop", 0) == 0) {
			for (auto reg = dup.regs.begin(); reg != dup.regs.end(); ++reg) {
				if (reg->num != 15)
					ins.push_back(vins::ins_ldr_postinc(*reg, vreg(29), 4));
				else
					ins.push_back(vins::ins_add(vreg(29), vreg(29), 4));
				ins.back().cond = cond;
				ins.back().mnemonic.append(cond);
			}
		}
		else if (dup.mnemonic.rfind("stm", 0) == 0) {
			// #TODO should we store twice?
			if (in->gen.size()) { // this instruction update the address register
				if (dup.mnemonic == "stm" || dup.mnemonic == "stm.w") {
					ins.push_back(vins::ins_add(dup.regs[0], dup.regs[0], 4 * in->regs.size() - 4));
					ins.back().cond = cond;
					ins.back().mnemonic.append(cond);
				}
				else if (dup.mnemonic == "stmdb" || dup.mnemonic == "stmdb.w") {
					ins.push_back(vins::ins_sub(dup.regs[0], dup.regs[0], 4 * in->regs.size() - 4));
					ins.back().cond = cond;
					ins.back().mnemonic.append(cond);
				}
				else {
					std::cerr << "Unrecognized instruction: " << dup << '\n';
					assert(0);
				}
			}
		}
		else if (dup.mnemonic.rfind("ldm", 0) == 0) {
			if (dup.gen.size() == dup.regs.size()) {
				if (dup.mnemonic == "ldm" || dup.mnemonic == "ldm.w")
					for (auto reg = ++dup.regs.begin(); reg != dup.regs.end(); ++reg) {
						ins.push_back(vins::ins_ldr_postinc(*reg, dup.regs[0], 4));
						ins.back().cond = cond;
						ins.back().mnemonic.append(cond);
					}
				else if (dup.mnemonic == "ldmdb" || dup.mnemonic == "ldmdb.w")
					for (auto reg = ++dup.regs.begin(); reg != dup.regs.end(); ++reg) {
						ins.push_back(vins::ins_ldr_preinc(*reg, dup.regs[0], -4));
						ins.back().cond = cond;
						ins.back().mnemonic.append(cond);
					}
				else {
					std::cerr << "Unrecognized instruction: " << dup << '\n';
					assert(0);
				}
			}
			else {
				int i = 0;
				if (dup.mnemonic == "ldm" || dup.mnemonic == "ldm.w")
					for (auto reg = ++dup.regs.begin(); reg != dup.regs.end(); ++reg) {
						ins.push_back(vins::ins_ldr(*reg, dup.regs[0], 4 * i++));
						ins.back().cond = cond;
						ins.back().mnemonic.append(cond);
					}
				else if (dup.mnemonic == "ldmdb" || dup.mnemonic == "ldmdb.w")
					for (auto reg = ++dup.regs.begin(); reg != dup.regs.end(); ++reg) {
						ins.push_back(vins::ins_ldr(*reg, dup.regs[0], -4 * --i));
						ins.back().cond = cond;
						ins.back().mnemonic.append(cond);
					}
				else {
					std::cerr << "Unrecognized instruction: " << dup << '\n';
					assert(0);
				}
			}
		}
		else {
			ins.push_back(dup);
		}
	}

	if (ins.size() == 0)
		return {};

	in->transfer_label(ins.front());

	return ins;
}

[[nodiscard]] static basic_block::iterator insert_check_store(
	lifter& lift,
	basic_block& bb,
	basic_block::iterator pos
) {
	basic_block ins;

	for (vreg r : pos->regs) {
		ins.push_back(vins::ins_cmp(duplicate(r), r));

		ins.push_back(vins::ins_b("ne", ".error_detected"));
	}

	ins.push_front(vins::ins_mrs(r_preserve_flags));
	ins.push_back(vins::ins_msr(r_preserve_flags));

	pos->transfer_label(ins.front());

	bb.splice(pos, ins);
	if (pos->gen.size())
		bb.splice(pos, duplicate(lift, &*pos));

	return std::next(pos);
}

[[nodiscard]] static basic_block::iterator insert_check_arguments(
	basic_block& bb,
	basic_block::iterator pos
) {
	basic_block ins;

	for (vreg r : {vreg(0), vreg(1), vreg(2), vreg(3)}) {
		ins.push_back(vins::ins_cmp(duplicate(r), r));

		ins.push_back(vins::ins_b("ne", ".error_detected"));
	}

	ins.push_front(vins::ins_mrs(r_preserve_flags));
	ins.push_back(vins::ins_msr(r_preserve_flags));

	pos->transfer_label(ins.front());

	bb.splice(pos, ins);

	for (vreg r : {vreg(0), vreg(1), vreg(2), vreg(3)}) {
		ins.push_back(vins::ins_mov(duplicate(r), r));
	}

	bb.splice(std::next(pos), ins);

	return std::next(pos, 5);
}

[[nodiscard]] static basic_block::iterator insert_check_return_value(
	lifter& lift,
	basic_block& bb,
	basic_block::iterator pos
) {
	basic_block ins;

	ins.push_back(vins::ins_mrs(r_preserve_flags));

	ins.push_back(vins::ins_cmp(duplicate(vreg(0)), vreg(0)));

	ins.push_back(vins::ins_b("ne", ".error_detected"));

	ins.push_back(vins::ins_msr(r_preserve_flags));

	pos->transfer_label(ins.front());

	bb.splice(pos, ins);
	if (pos->mnemonic == "ldr" || pos->mnemonic == "ldr.w") {
		assert(pos->regs.size() == 2);
		assert(pos->regs[0].num == 15);
		assert(pos->regs[1].num == 13);
		assert(pos->imm() == 4);
		assert(pos->operands == "%0, [%1], #%i");
		bb.insert(pos, vins::ins_add(duplicate(vreg(13)), duplicate(vreg(13)), 4));
	}
	else if (pos->mnemonic == "pop" || pos->mnemonic == "pop.w") {
		bb.splice(pos, duplicate(lift, &*pos));
	}

	return std::next(pos);
}

static int rand_sig() {
	static std::mt19937 gen_rand;
	return 0xff & gen_rand();
};

static std::string negate_condition(const std::string& cond) {
	if      (cond == "ne") return "eq";
	else if (cond == "eq") return "ne";
	else if (cond == "cs" ||
	         cond == "hs") return "cc";
	else if (cond == "cc" ||
	         cond == "lo") return "cs";
	else if (cond == "mi") return "pl";
	else if (cond == "pl") return "mi";
	else if (cond == "vs") return "vc";
	else if (cond == "vc") return "vs";
	else if (cond == "hi") return "ls";
	else if (cond == "ls") return "hi";
	else if (cond == "ge") return "lt";
	else if (cond == "lt") return "ge";
	else if (cond == "gt") return "le";
	else if (cond == "le") return "gt";
	else assert(0);
}

static bool has_store(const basic_block& bb) {
	for (const auto& in : bb) {
		if (in.mnemonic.rfind("str", 0) == 0)
			return true;
		else if (in.mnemonic.rfind("stm", 0) == 0)
			return true;
	}

	return false;
}

static std::map<const basic_block*, vreg> apply_cfc(
	basic_block& bb,
	const std::map<basic_block*, int>& sigs
) {
	static int label_count = 0;
	static std::map<const basic_block*, vreg> ret_sig_regs;

	if (bb.visited)
		return ret_sig_regs;
	bb.visited = true;

	basic_block::iterator pos;

	int signature = sigs.at(&bb);
	if (bb.front().is_pseudo() && bb.front().operands == "func_entry") {
		pos = std::next(bb.begin());
		bb.insert(pos, vins::ins_mov(r_gsr, signature));
	}
	else {
		pos = bb.begin();
		bb.insert(pos, vins::ins_xor(r_gsr, r_gsr, r_rts));
		pos->transfer_label(bb.front());
	}

	if (has_store(bb)) {
		bb.insert(pos, vins::ins_cmp(r_gsr, signature));
		bb.insert(pos, vins::ins_b("ne", ".error_detected"));
	}

	for (auto in = bb.begin(); in != bb.end(); ++in) {
		if (in->is_call() && !in->is_local_call()) {
			bb.insert(in, vins::ins_cmp(r_gsr, signature));
			bb.insert(in, vins::ins_b("ne", ".error_detected"));
		}
	}

	if (bb.back().is_pseudo() && bb.back().operands == "func_exit") {
		pos = std::prev(bb.end(), 2);
		assert(pos->is_function_return());

		bb.insert(pos, vins::ins_cmp(r_gsr, signature));
		bb.insert(pos, vins::ins_b("ne", ".error_detected"));
	}
	else if (bb.back().is_function_return()) {
		pos = std::prev(bb.end());

		assert(bb.successors.size());

		vreg ret_sig_reg = new_ret_sig();

		for (basic_block* succ : bb.successors) {
			ret_sig_regs.insert({succ, ret_sig_reg});
		}
		

		vins tmp = vins::ins_xor(r_rts, ret_sig_reg, signature);
		pos->transfer_label(tmp);
		bb.insert(pos, std::move(tmp));
	}
	else if (bb.back().is_local_call()) {
		pos = std::prev(bb.end());

		int sig_next = sigs.at(bb.successors[0]);
		vins tmp = vins::ins_mov(r_rts, sig_next ^ signature);
		pos->transfer_label(tmp);
		bb.insert(pos, std::move(tmp));
	}
	else if (bb.successors.size() == 1) {
		if (bb.back().is_jump())
			pos = std::prev(bb.end());
		else
			pos = bb.end();
		int sig_next = sigs.at(bb.successors[0]);
		vins tmp = vins::ins_mov(r_rts, sig_next ^ signature);
		if (pos != bb.end())
			pos->transfer_label(tmp);
		bb.insert(pos, std::move(tmp));
	}
	else if (bb.successors.size() == 2) {
		std::string cond = bb.back().cond;
		assert(cond.size());
		assert(bb.back().is_jump() == true);

		auto it = bb.rbegin();
		for (; it != bb.rend(); ++it) {
			if (it->update_flags() && std::next(it)->update_flags()) {
				break;
			}
		}
		pos = std::prev(it.base());
		assert(pos->update_flags());
		assert(std::prev(pos)->update_flags());

		{
			int sig_next = sigs.at(bb.successors[0]);
			vins tmp = vins::ins_mov(r_rts, sig_next ^ signature);
			
			tmp.cond = cond;
			tmp.mnemonic.append(cond);
			pos->transfer_label(tmp);
			bb.insert(pos, std::move(tmp));
		}
		{
			int sig_next = sigs.at(bb.successors[1]);
			vins tmp = vins::ins_mov(r_rts, sig_next ^ signature);
			
			tmp.cond = negate_condition(cond);
			tmp.mnemonic.append(tmp.cond);
			bb.insert(pos, std::move(tmp));
		}
	}
	else {
		for (auto& in : bb)
			std::cout << in << '\n';
		std::cerr << "Unexpected instruction: " << bb.back() << '\n';
		assert(0);
	}

	return ret_sig_regs;
}

static void apply_cfc_return_signature(
	control_flow_graph& cfg,
	const std::map<basic_block*, int>& sigs,
	const std::map<const basic_block*, vreg>& ret_sigs) {
	for (auto& bb : cfg) {
		if (bb.back().is_local_call()) {
			auto pos = std::prev(bb.end());

			basic_block *ret_bb = bb.next;

			vreg ret_sig_reg = ret_sigs.at(ret_bb);
			int ret_sig_value = sigs.at(ret_bb);

			vins tmp = vins::ins_mov(ret_sig_reg, ret_sig_value);
			pos->transfer_label(tmp);
			bb.insert(pos, std::move(tmp));
		}
	}
}

void apply_cfc(control_flow_graph& cfg) {
	std::map<basic_block*, int> sigs;
	std::map<const basic_block*, vreg> ret_sigs;

	for (auto& bb : cfg) {
		sigs.insert({&bb, rand_sig()});
	}

	for (auto& bb : cfg) {
		if (!bb.front().is_data()) {
			ret_sigs.merge(apply_cfc(bb, sigs));
		}
	}

	for (auto& bb : cfg) {
		assert(bb.front().is_data() || bb.visited);
	}

	apply_cfc_return_signature(cfg, sigs, ret_sigs);

	cfg.push_back({vins::ins_udf()});
	cfg.back().back().label = ".error_detected";
}

void apply_swift(lifter& lift, control_flow_graph& cfg) {
	for (basic_block& bb : cfg) {
		if (bb.front().is_data())
			continue;
		basic_block::iterator in = bb.begin();

		while (in != bb.end()) {
			if (in->is_pseudo()) {
				++in;
				continue;
			}

			while (in != bb.end() && !is_sync_point(*in)) {
				bb.splice(in, duplicate(lift, &*in));
				in++;
			}
			
			if (in != bb.end() && is_sync_point(*in)) {
				if (in->mnemonic.rfind("str", 0) == 0)
					in = insert_check_store(lift, bb, in);
				else if (in->mnemonic.rfind("stm", 0) == 0)
					in = insert_check_store(lift, bb, in);
				else if (in->is_call() && !in->is_local_call())
					in = insert_check_arguments(bb, in);
				else if (in->is_function_return()) 
					in = insert_check_return_value(lift, bb, in);
				else
					++in;
			}
		}
	}

	apply_cfc(cfg);

	duplicate_registers(cfg);
}
