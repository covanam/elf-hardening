#include "cfg.h"
#include <random>
#include <map>
#include <tuple>
#include <cassert>

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

	/* step 2 */
	int subRanPrevVal, signature;
	std::tie(signature, subRanPrevVal) = sigs.at(&bb);
	if (bb.front().is_pseudo() && bb.front().operands == "func_entry") {
		pos = std::next(bb.begin());
		bb.insert(pos, vins::ins_mov(sig_reg, signature));
	}
	else {
		pos = bb.begin();
		bb.insert(pos, vins::ins_sub(sig_reg, sig_reg, subRanPrevVal));
		pos->transfer_label(bb.front());
	}

	/* step 3 */
	if (pos->label.empty()) {
		pos->label = ".sig_check_ok_" + std::to_string(label_count++);
	}
	std::string label = pos->label;
	bb.insert(pos, vins::ins_cmp(sig_reg, signature));
	bb.insert(pos, vins::ins_b("eq", label.c_str()));
	bb.insert(pos, vins::ins_udf());

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
		int adjustValue = (randomNumberSuccs + subRanPrevValSuccs) - signature;
		if (adjustValue > 0)
			bb.insert(pos, vins::ins_sub(sig_reg, sig_reg, adjustValue));
		else
			bb.insert(pos, vins::ins_add(sig_reg, sig_reg, -adjustValue));
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
	}
	else if (bb.successors.size() == 2) {
		std::string cond = bb.back().cond;
		assert(cond.size());
		assert(bb.back().is_jump() == true);
		{
			pos = std::prev(bb.end());
			int randomNumberSuccs, subRanPrevValSuccs;
			std::tie(randomNumberSuccs, subRanPrevValSuccs) = sigs.at(bb.successors[0]);
			int adjustValue = (randomNumberSuccs + subRanPrevValSuccs) - signature;
			vins tmp;
			if (adjustValue > 0)
				tmp = vins::ins_sub(sig_reg, sig_reg, adjustValue);
			else
				tmp = vins::ins_add(sig_reg, sig_reg, -adjustValue);
			
			tmp.cond = cond;
			tmp.mnemonic.append(cond);
			bb.insert(pos, std::move(tmp));
		}
		{
			pos = bb.end();
			int randomNumberSuccs, subRanPrevValSuccs;
			std::tie(randomNumberSuccs, subRanPrevValSuccs) = sigs.at(bb.successors[1]);
			int adjustValue = (randomNumberSuccs + subRanPrevValSuccs) - signature;
			vins tmp;
			if (adjustValue > 0)
				tmp = vins::ins_sub(sig_reg, sig_reg, adjustValue);
			else
				tmp = vins::ins_add(sig_reg, sig_reg, -adjustValue);
			
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
	else if (bb.successors.size() > 2) {
		assert(bb.back().is_function_return() ||
			bb.back().is_pseudo() && bb.back().operands == "func_exit");
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
	vreg sig_reg(16);

	for (auto& bb : cfg) {
		if (false == bb.visited && !bb.front().is_data()) {
			assert(sig_reg.num < 64);
			apply_rasm_bb(bb, sig_reg, sigs);
			sig_reg.num++;
		}
	}
}
