#include "reg-alloc.h"
#include "cfg.h"
#include <map>
#include "disasm.h"
#include <cassert>

static void duplicate_registers(control_flow_graph& cfg) {
	for (auto& bb : cfg) {
		if (bb.front().is_pseudo() && bb.front().operands == "func_entry") {
			basic_block dup({
				vins::ins_mov(vreg(16), vreg(0)),
				vins::ins_mov(vreg(17), vreg(1)),
				vins::ins_mov(vreg(18), vreg(2)),
				vins::ins_mov(vreg(19), vreg(3)),
				vins::ins_mov(vreg(20), vreg(4)),
				vins::ins_mov(vreg(21), vreg(5)),
				vins::ins_mov(vreg(22), vreg(6)),
				vins::ins_mov(vreg(23), vreg(7)),
				vins::ins_mov(vreg(24), vreg(8)),
				vins::ins_mov(vreg(25), vreg(9)),
				vins::ins_mov(vreg(26), vreg(10)),
				vins::ins_mov(vreg(27), vreg(11)),
				vins::ins_mov(vreg(28), vreg(12)),
				vins::ins_mov(vreg(29), vreg(13)),
				vins::ins_mov(vreg(30), vreg(14))
			});
			bb.splice(std::next(bb.begin()), dup);
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

static basic_block duplicate(basic_block::iterator begin, basic_block::iterator end) {
	if (begin == end)
		return {};

	basic_block ins;

	bool use_flags = false;
	bool update_flags = false;

	for (auto in = begin; in != end; ++in) {
		if (in->is_pseudo())
			continue;

		if (in->use_flags())
			use_flags = true;
		
		if (in->update_flags())
			update_flags = true;

		vins dup = *in;
		dup.label.clear();

		for (vreg& r : dup.regs) {
			r = duplicate(r);
		}

		if (dup.mnemonic.rfind("push", 0) == 0) {
			// #TODO should we push twice?
			ins.push_back(vins::ins_sub(vreg(29), vreg(29), 4 * in->regs.size()));
		}
		else if (dup.mnemonic.rfind("pop", 0) == 0) {
			for (auto reg = ++dup.regs.begin(); reg != dup.regs.end(); ++reg) {
				ins.push_back(vins::ins_ldr_postinc(*reg, vreg(29), 4));
			}
		}
		else if (dup.mnemonic.rfind("stm", 0) == 0) {
			// #TODO should we store twice?
			if (in->gen.size()) { // this instruction update the address register
				if (dup.mnemonic == "stm" || dup.mnemonic == "stm.w")
					ins.push_back(vins::ins_add(dup.regs[0], dup.regs[0], 4 * in->regs.size() - 4));
				else if (dup.mnemonic == "stmdb" || dup.mnemonic == "stmdb.w")
					ins.push_back(vins::ins_sub(dup.regs[0], dup.regs[0], 4 * in->regs.size() - 4));
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
					}
				else if (dup.mnemonic == "ldmdb" || dup.mnemonic == "ldmdb.w")
					for (auto reg = ++dup.regs.begin(); reg != dup.regs.end(); ++reg) {
						ins.push_back(vins::ins_ldr_preinc(*reg, dup.regs[0], -4));
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
					}
				else if (dup.mnemonic == "ldmdb" || dup.mnemonic == "ldmdb.w")
					for (auto reg = ++dup.regs.begin(); reg != dup.regs.end(); ++reg) {
						ins.push_back(vins::ins_ldr(*reg, dup.regs[0], -4 * --i));
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

	if (update_flags) {
		// save it to compare with original later
		ins.push_back(vins::ins_mrs(vreg(32)));
	}
	if (use_flags) {
		// preserve flags as it is used my original instructions
		ins.push_front(vins::ins_mrs(vreg(31)));
		ins.push_back(vins::ins_msr(vreg(31)));
	}

	begin->transfer_label(ins.front());

	return ins;
}

static void insert_check_store(basic_block& bb, basic_block::iterator pos) {
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

	ins.push_front(vins::ins_mrs(vreg(31)));
	ins.push_back(vins::ins_msr(vreg(31)));
	ins.back().label = label;

	pos->transfer_label(ins.front());

	bb.splice(pos, ins);
	bb.splice(pos, duplicate(pos, std::next(pos)));
}

static void insert_check_cond(
	basic_block& bb, basic_block::iterator pos
) {
	static int label_counter = 0;

	basic_block ins;
	std::string label = ".check_cond_okay_" + std::to_string(label_counter);
	++label_counter;

	// mrs r32, aprs
	ins.push_back(vins::ins_mrs(vreg(31)));

	// cmp r31, r32
	ins.push_back(vins::ins_cmp(vreg(31), vreg(32)));

	// beq .check_cond_okay_#n
	ins.push_back(vins::ins_b("eq", label.c_str()));

	// udf
	ins.push_back(vins::ins_udf());

	// .check_cond_okay: msr apsr, r32
	ins.push_back(vins::ins_msr(vreg(31)));
	ins.back().label = label;

	pos->transfer_label(ins.front());

	bb.splice(pos, ins);
}

static void insert_check_arguments(basic_block& bb, basic_block::iterator pos) {
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

	ins.push_front(vins::ins_mrs(vreg(31)));
	ins.push_back(vins::ins_msr(vreg(31)));
	ins.back().label = label;

	pos->transfer_label(ins.front());

	bb.splice(pos, ins);
}

static void insert_check_return_value(basic_block& bb, basic_block::iterator pos) {
	static int label_counter = 0;

	std::string label = ".check_retval_okay_" + std::to_string(label_counter);
	++label_counter;

	basic_block ins;

	ins.push_back(vins::ins_mrs(vreg(31)));

	ins.push_back(vins::ins_cmp(duplicate(vreg(0)), vreg(0)));

	ins.push_back(vins::ins_b("eq", label.c_str()));

	ins.push_back(vins::ins_udf());

	ins.push_back(vins::ins_msr(vreg(31)));
	ins.back().label = label;

	pos->transfer_label(ins.front());

	bb.splice(pos, ins);
	bb.splice(pos, duplicate(pos, std::next(pos)));
}

void apply_eddi(control_flow_graph& cfg) {
	for (basic_block& bb : cfg) {
		if (bb.front().is_data())
			continue;
		basic_block::iterator dup_start = bb.begin(), dup_end = bb.begin();
		if (bb.front().is_pseudo()) {
			++dup_start;
			++dup_end;
		}

		while (dup_start != bb.end() || dup_end != bb.end()) {
			while (dup_end != bb.end() && !is_sync_point(*dup_end))
				++dup_end;

			bb.splice(dup_start, duplicate(dup_start, dup_end));
			
			if (dup_end != bb.end() && is_sync_point(*dup_end)) {
				if (dup_end->is_jump() && !dup_end->cond.empty())
					insert_check_cond(bb, dup_end);
				else if (dup_end->mnemonic.rfind("str", 0) == 0)
					insert_check_store(bb, dup_end);
				else if (dup_end->mnemonic.rfind("stm", 0) == 0)
					insert_check_store(bb, dup_end);
				else if (dup_end->is_call() && !dup_end->is_local_call())
					insert_check_arguments(bb, dup_end);
				else if (dup_end->is_function_return()) 
					insert_check_return_value(bb, dup_end);

				++dup_end;
			}

			dup_start = dup_end;
		}
	}

	duplicate_registers(cfg);
}
