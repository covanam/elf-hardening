/*
TODO:
3.2 Eliminating the Memory Penalty (DONE)
3.3 Control Flow Checking
3.4 Enhanced Control Flow Checking
3.5.1 Control Flow Checking at Blocks with Stores
3.5.2 Redundancy in Branch/Control Flow Checking
4.1 Function calls
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
	static int label_counter = 0;

	basic_block ins;
	std::string label;

	for (vreg r : pos->regs) {
		ins.push_back(vins::ins_cmp(duplicate(r), r));
		ins.back().label = label;

		label = ".check_okay_" + std::to_string(label_counter);
		++label_counter;
		ins.push_back(vins::ins_b("eq", label.c_str()));

		ins.push_back(vins::ins_udf());
	}

	ins.push_front(vins::ins_mrs(r_preserve_flags));
	ins.push_back(vins::ins_msr(r_preserve_flags));
	ins.back().label = label;

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
	static int label_counter = 0;

	basic_block ins;
	std::string label;

	for (vreg r : {vreg(0), vreg(1), vreg(2), vreg(3)}) {
		ins.push_back(vins::ins_cmp(duplicate(r), r));
		ins.back().label = label;

		label = ".check_args_okay_" + std::to_string(label_counter);
		++label_counter;
		ins.push_back(vins::ins_b("eq", label.c_str()));

		ins.push_back(vins::ins_udf());
	}

	ins.push_front(vins::ins_mrs(r_preserve_flags));
	ins.push_back(vins::ins_msr(r_preserve_flags));
	ins.back().label = label;

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
	static int label_counter = 0;

	std::string label = ".check_retval_okay_" + std::to_string(label_counter);
	++label_counter;

	basic_block ins;

	ins.push_back(vins::ins_mrs(r_preserve_flags));

	ins.push_back(vins::ins_cmp(duplicate(vreg(0)), vreg(0)));

	ins.push_back(vins::ins_b("eq", label.c_str()));

	ins.push_back(vins::ins_udf());

	ins.push_back(vins::ins_msr(r_preserve_flags));
	ins.back().label = label;

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

int rand() {
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

static void apply_rasm_bb(
	basic_block& bb,
	vreg sig_reg,
	const std::map<basic_block*, std::pair<int, int>>& sigs
) {
	static int label_count = 0;

	if (bb.visited)
		return;
	bb.visited = true;

	basic_block::iterator pos;

	int subRanPrevVal, signature;
	std::tie(signature, subRanPrevVal) = sigs.at(&bb);
	if (bb.front().is_pseudo() && bb.front().operands == "func_entry" ||
	    bb.front().label.size() && bb.front().label[0] != '.') {
		pos = std::next(bb.begin());
		bb.insert(pos, vins::ins_mov(sig_reg, signature));
	}
	else {
		/* step 2 */
		pos = bb.begin();
		bb.insert(pos, vins::ins_sub(sig_reg, sig_reg, subRanPrevVal));
		pos->transfer_label(bb.front());

		/* step 3 */
		if (pos->label.empty()) {
			pos->label = ".sig_check_ok_" + std::to_string(label_count++);
		}
		std::string label = pos->label;
		bb.insert(pos, vins::ins_cmp(sig_reg, signature));
		bb.insert(pos, vins::ins_b("eq", label.c_str()));
		bb.insert(pos, vins::ins_udf());
	}

	/* step 4 */
	if (bb.back().is_pseudo() && bb.back().operands == "func_exit" ||
	    bb.back().is_function_return()) {
		if (bb.back().is_pseudo())
			pos = std::prev(bb.end(), 2);
		else
			pos = std::prev(bb.end());

		assert(pos->is_function_return());

		int returnValue = rand();
		int adjustValue = signature - returnValue;
		if (adjustValue > 0) {
			bb.insert(pos, vins::ins_sub(sig_reg, sig_reg, adjustValue));
		}
		else {
			bb.insert(pos, vins::ins_add(sig_reg, sig_reg, -adjustValue));
		}

		if (pos != bb.end())
			pos->transfer_label(*std::prev(pos));

		if (pos->label.empty()) {
			pos->label = ".sig_check_ok_" + std::to_string(label_count++);
		}
		std::string label = pos->label;
		bb.insert(pos, vins::ins_cmp(sig_reg, returnValue));
		bb.insert(pos, vins::ins_b("eq", label.c_str()));
		bb.insert(pos, vins::ins_udf());
	}
	else if (bb.back().is_local_call()) {
		pos = std::prev(bb.end());
		int randomNumberSuccs, subRanPrevValSuccs;
		std::tie(randomNumberSuccs, subRanPrevValSuccs) = sigs.at(bb.next);
		int adjustValue = signature - (randomNumberSuccs + subRanPrevValSuccs);
		if (adjustValue > 0)
			bb.insert(pos, vins::ins_sub(sig_reg, sig_reg, adjustValue));
		else
			bb.insert(pos, vins::ins_add(sig_reg, sig_reg, -adjustValue));
		
		pos->transfer_label(*std::prev(pos));
	}
	else if (bb.successors.size() == 1) {
		if (bb.back().is_jump())
			pos = std::prev(bb.end());
		else
			pos = bb.end();
		int randomNumberSuccs, subRanPrevValSuccs;
		std::tie(randomNumberSuccs, subRanPrevValSuccs) = sigs.at(bb.successors[0]);
		int adjustValue = signature - (randomNumberSuccs + subRanPrevValSuccs);
		if (adjustValue > 0)
			bb.insert(pos, vins::ins_sub(sig_reg, sig_reg, adjustValue));
		else
			bb.insert(pos, vins::ins_add(sig_reg, sig_reg, -adjustValue));
		
		if (pos != bb.end())
			pos->transfer_label(*std::prev(pos));
	}
	else if (bb.successors.size() == 2) {
		std::string cond = bb.back().cond;
		assert(cond.size());
		assert(bb.back().is_jump() == true);
		{
			pos = std::prev(bb.end());
			int randomNumberSuccs, subRanPrevValSuccs;
			std::tie(randomNumberSuccs, subRanPrevValSuccs) = sigs.at(bb.successors[0]);
			int adjustValue = signature - (randomNumberSuccs + subRanPrevValSuccs);
			vins tmp;
			if (adjustValue > 0)
				tmp = vins::ins_sub(sig_reg, sig_reg, adjustValue);
			else
				tmp = vins::ins_add(sig_reg, sig_reg, -adjustValue);
			
			tmp.cond = cond;
			tmp.mnemonic.append(cond);
			pos->transfer_label(tmp);
			bb.insert(pos, std::move(tmp));
		}
		{
			int randomNumberSuccs, subRanPrevValSuccs;
			std::tie(randomNumberSuccs, subRanPrevValSuccs) = sigs.at(bb.successors[1]);
			int adjustValue = signature - (randomNumberSuccs + subRanPrevValSuccs);
			vins tmp;
			if (adjustValue > 0)
				tmp = vins::ins_sub(sig_reg, sig_reg, adjustValue);
			else
				tmp = vins::ins_add(sig_reg, sig_reg, -adjustValue);
			
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

	if (bb.back().is_local_call()) {
		apply_rasm_bb(*bb.next, sig_reg, sigs);
	}
	else if (bb.back().is_function_return() ||
	         bb.back().is_pseudo() && bb.back().operands == "func_exit") {
		/* do not follow function return */
	}
	else {
		for (auto succ : bb.successors)
			apply_rasm_bb(*succ, sig_reg, sigs);
	}
}

void apply_rasm(control_flow_graph& cfg) {

	/* step 1 */
	std::map<basic_block*, std::pair<int, int>> sigs;
	for (auto& bb : cfg) {
		std::pair<int, int> sig_and_subVal = {rand(), rand()};
		sigs.insert({&bb, std::move(sig_and_subVal)});
	}

	cfg.reset();
	vreg sig_reg(33);

	for (auto& bb : cfg) {
		if (false == bb.visited && !bb.front().is_data()) {
			assert(sig_reg.num < 64);
			apply_rasm_bb(bb, sig_reg, sigs);
			sig_reg.num++;
		}
	}

	for (auto& bb : cfg) {
		assert(bb.front().is_data() || bb.visited);
	}

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

	duplicate_registers(cfg);
}
