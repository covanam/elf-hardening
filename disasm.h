#include <elfio/elfio.hpp>
#include <cstdint>
#include <capstone/capstone.h>
#include <list>

struct bunit {
	std::vector<uint8_t> raw;
	cs_insn in;
	uint64_t addr;
	uint64_t new_addr;
	cs_detail detail;

	bool rel;
	uint64_t target_addr;

	bunit(const cs_insn &p) {
		in = p;
		this->addr = p.address;
		raw.assign(p.bytes, p.bytes + p.size);
		detail = *p.detail;
		calculate_relative_address();
	}
	bunit(const uint8_t *data, uint64_t size, uint64_t addr) {
		raw.assign(data, data + size);
		this->addr = addr;
		this->rel = false;
		in.id = 0; // invalid instruction, to mark this struct as data
	}

	int size() const {
		return raw.size();
	}

	friend std::ostream& operator<<(std::ostream& os, const bunit &b) {
		os << b.in.mnemonic << ' ';
		if (b.rel) {
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

			uint64_t pc = (b.addr + 4) & ~(uint64_t)2;
			int imm = b.target_addr - pc;
			os << imm;
			os << (b.in.op_str + j);
		} else {
			os << b.in.op_str;
		}
		return os;
	}

private:
	void calculate_relative_address() {
		bool use_pc = false;
		bool use_imm = false;
		int imm;

		if (in.id == 0) {
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

void dump_text(ELFIO::elfio& writer, const std::list<bunit> &d);
