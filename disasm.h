#include <elfio/elfio.hpp>
#include <cstdint>
#include <capstone/capstone.h>
#include <list>

struct bunit {
	uint8_t data;
	cs_insn in;
	uint64_t addr;
	uint64_t new_addr;
	cs_detail detail;

	bunit *target;

	bunit(const cs_insn &p) {
		in = p;
		this->addr = p.address;
		detail = *p.detail;
		target = nullptr;
	}
	bunit(uint8_t data, uint64_t addr) {
		this->data = data;
		this->addr = addr;
		in.id = 0; // invalid instruction, to mark this struct as data
		target = nullptr;
	}
	bunit(const std::string s, uint64_t addr);

	int size() const {
		if (in.id != 0)
			return in.size;
		return 1;
	}

	friend std::ostream& operator<<(std::ostream& os, const bunit &b) {
		os << b.in.mnemonic << ' ';
		if (b.target) {
			int i, j;
			for (i = 0; b.in.op_str[i] != '#'; ++i);
			j = i + 1;
			while (true) {
				char c = b.in.op_str[j];
				if (c == 'x' || '0' <= c && c <= '9'
					|| 'a' <= c && c <= 'f'
					|| 'A' <= c && c <= 'F') {
					++j;
					continue;
				}
				break;
			}
			os.write(b.in.op_str, i + 1);

			int imm;
			if (b.is_branch_relative()) {
				imm = b.target->addr - b.addr;
			} else {
				uint64_t pc = (b.addr + 4) & ~(uint64_t)2;
				imm = b.target->addr - pc;
			}

			os << imm;
			os << (b.in.op_str + j);
		} else {
			os << b.in.op_str;
		}
		return os;
	}

	bool calculate_target_address(uint64_t *addr) {
		bool use_pc = false;
		bool use_imm = false;
		int imm;

		if (in.id == 0) {
			return false;
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

		for (int i = 0; i < detail.groups_count; ++i) {
			if (detail.groups[i] == ARM_GRP_BRANCH_RELATIVE) {
				*addr = imm;
				return true;
			}
		}

		if (use_pc && use_imm) {
			uint64_t pc = (this->addr + 4) & ~(uint64_t)2;
			*addr = pc + imm;
			return true;
		} else {
			return false;;
		}
	}

	bool is_branch_relative() const {
		if (in.id == 0)
			return false;

		for (int i = 0; i < detail.groups_count; ++i) {
			if (detail.groups[i] == ARM_GRP_BRANCH_RELATIVE) {
				return true;
			}
		}
		return false;
	}
};

std::list<bunit> disassemble(const ELFIO::elfio& reader);

void dump_text(ELFIO::elfio& writer, const std::list<bunit> &d);

void calculate_target(std::list<bunit> &x);
