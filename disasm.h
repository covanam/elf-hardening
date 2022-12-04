#include <elfio/elfio.hpp>
#include <cstdint>
#include <capstone/capstone.h>
#include <list>

struct bunit {
	const uint8_t *data;
	cs_insn in;
	uint64_t addr;
	uint64_t new_addr;
	int size;
	cs_detail detail;

	bool rel;
	uint64_t target_addr;

	bunit(const cs_insn &p) {
		in = p;
		this->addr = p.address;
		this->data = nullptr;
		this->size = p.size;
		detail = *p.detail;
		calculate_relative_address();
	}
	bunit(const uint8_t *data, uint64_t size, uint64_t addr) {
		this->data = data;
		this->size = size;
		this->addr = addr;
		this->rel = false;
	}

private:
	void calculate_relative_address() {
		bool use_pc = false;
		bool use_imm = false;
		int imm;

		if (data != nullptr) {
			rel = false;
			return;
		}
		for (
			const cs_arm_op *op = detail.arm.operands;
			op < detail.arm.operands + detail.arm.op_count;
			++op
		) {
			switch (op->type) {
			case ARM_OP_MEM:
				use_imm = true;
				imm = op->mem.disp;
				if (op->mem.base == ARM_REG_PC)
					use_pc = true;
				break;
			case ARM_OP_REG:
				if (op->reg == ARM_REG_PC)
					use_pc = true;
				break;
			case ARM_OP_IMM:
				use_imm = true;
				imm = op->imm;
				break;
			default:
				break;
			}
		}
		if (use_pc && use_imm) {
			uint64_t pc = (addr + 4) & ~(uint64_t)2;
			target_addr = pc + imm;
			rel = true;
		} else {
			rel = false;
		}
	}
};

std::list<bunit> disassemble(const ELFIO::elfio& reader);
