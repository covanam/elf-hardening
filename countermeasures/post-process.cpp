#include "disasm.h"
#include <cassert>
#include "cfg.h"

void mitigate_second_stack_vunerabilities(control_flow_graph& cfg) {
	for (auto& bb : cfg) {
		if (bb.front().is_pseudo() && bb.front().operands == "func_entry") {
			auto sig_init = bb.begin();
			for(; sig_init != bb.end(); ++sig_init) {
				if (sig_init->mnemonic == "mov" && sig_init->regs.size() == 1)
					break;
			}
			assert(sig_init != bb.end());

			vreg sig_reg = sig_init->regs[0];
			int sig_value = sig_init->imm();

			*sig_init = vins::ins_ldr(sig_reg, vreg(13), -4);

			auto pos = std::next(bb.begin());
			
			bb.insert(pos, vins::ins_mov(vreg(12), sig_value));
			bb.insert(pos, vins::ins_str(vreg(12), vreg(13), -4));

			bb.push_front(vins::ins_udf());
		}

		if (bb.back().is_pseudo() && bb.back().operands == "func_exit") {
			auto sig_cmp = std::prev(bb.end());
			for (; sig_cmp != bb.begin(); --sig_cmp) {
				if (sig_cmp->mnemonic == "cmp" && sig_cmp->regs.size() == 1)
					break;
			}
			assert(sig_cmp != bb.begin() && std::next(sig_cmp)->mnemonic == "bne");

			int sig_value = sig_cmp->imm();
			vreg sig_reg = sig_cmp->regs[0];

			*sig_cmp = vins::ins_str(sig_reg, vreg(13), -4);
			bb.erase(std::next(sig_cmp));

			auto pos = std::prev(bb.end(), 2);
			assert(pos->is_function_return());

			bb.insert(pos, vins::ins_ldr(vreg(12), vreg(13), -4));
			bb.insert(pos, vins::ins_cmp(vreg(12), sig_value));
			bb.insert(pos, vins::ins_b("ne", ".error_detected"));
		}
	}
}
