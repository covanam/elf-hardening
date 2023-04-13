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
	if (in.is_jump())
		return true;
	
	return false;
}

static basic_block duplicate(basic_block::iterator begin, basic_block::iterator end) {
	if (begin == end)
		return {};

	basic_block ins;

	for (auto in = begin; in != end; ++in) {
		if (in->is_pseudo())
			continue;

		vins dup = *in;
		dup.label.clear();

		for (vreg& r : dup.regs) {
			assert(r.num < 16);
			r.num += 16;
		}

		if (dup.mnemonic.rfind("push", 0) == 0) {
			// #TODO
			ins.push_back(vins::ins_sub(vreg(29), vreg(29), 4 * in->regs.size()));
		}
		else if (dup.mnemonic.rfind("pop", 0) == 0) {
			for (auto reg = ++dup.regs.begin(); reg != dup.regs.end(); ++reg) {
				ins.push_back(vins::ins_mov(*reg, vreg(reg->num - 16)));
			}
		}
		else if (dup.mnemonic.rfind("stm", 0) == 0) {
			// #TODO
			if (in->gen.size()) // this instruction update the address register
				ins.push_back(vins::ins_add(dup.regs[0], dup.regs[0], 4 * in->regs.size() - 4));;
		}
		else if (dup.mnemonic.rfind("ldm", 0) == 0) {
			for (auto reg = ++dup.regs.begin(); reg != dup.regs.end(); ++reg) {
				ins.push_back(vins::ins_mov(*reg, vreg(reg->num - 16)));
			}
		}
		else {
			ins.push_back(dup);
		}
	}

	//#TODO this can be redundant
	ins.push_front(vins::ins_mrs(vreg(31)));
	ins.push_back(vins::ins_mrs(vreg(32)));
	ins.push_back(vins::ins_msr(vreg(31)));

	begin->transfer_label(ins.front());

	return ins;
}

template<typename list> static void insert_check_store(
	basic_block& bb, basic_block::iterator pos,
	list regs
) {
	static int label_counter = 0;

	basic_block ins;
	std::string label;

	for (vreg r : regs) {
		vins tmp = vins::ins_mrs(vreg(31));
		tmp.label = label;
		ins.push_back(std::move(tmp));

		ins.push_back(vins::ins_cmp(vreg(r.num + 16), r));

		label = ".check_okay_" + std::to_string(label_counter);
		++label_counter;
		ins.push_back(vins::ins_b("eq", label.c_str()));

		ins.push_back(vins::ins_udf());

		ins.push_back(vins::ins_msr(vreg(31)));
	}

	pos->transfer_label(ins.front());
	pos->label = label;

	bb.splice(pos, ins);
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

void apply_eddi(control_flow_graph& cfg) {
	int in_start = 0;
	int in_end = 0;
	int in_num = -1;

	for (basic_block& bb : cfg) {
		basic_block::iterator dup_start = bb.begin(), dup_end = bb.begin();
		if (bb.front().is_pseudo()) {
			++dup_start;
			++dup_end;
		}

		while (dup_start != bb.end() || dup_end != bb.end()) {
			while (dup_end != bb.end() && !is_sync_point(*dup_end))
				++dup_end;

			in_num++;

			if (in_num >= in_start && in_num <= in_end)
				bb.splice(dup_start, duplicate(dup_start, dup_end));
			
			if (dup_end != bb.end() && is_sync_point(*dup_end)) {
				if (in_num >= in_start && in_num <= in_end) {
					if (dup_end->is_jump() && !dup_end->cond.empty())
						insert_check_cond(bb, dup_end);
				}
				++dup_end;
			}

			dup_start = dup_end;
		}
	}

	duplicate_registers(cfg);
}
