#include <elfio/elfio.hpp>
#include <cstdint>
#include <capstone/capstone.h>
#include <list>
#include <sstream>

struct vins {
	std::string mnemonic;
	std::string operands;
	cs_insn in;
	uint64_t addr;
	cs_detail detail;

	std::string target_label;
	std::string label;

	vins(const cs_insn &in) {
		this->in = in;
		this->addr = in.address;
		detail = *in.detail;

		mnemonic = in.mnemonic;
		operands = in.op_str;

		uint64_t dum;
		if (calculate_target_address(&dum)) {
			char c;
			int i = 0;
			while (true) {
				c = operands[i];
				if (c == '#' || c == '[' || c == 0)
					break;
				++i;
			}
			if (c == '#' || c == '[')
				operands = operands.substr(0, i) + "%m";
		}
	}
	vins(uint8_t data, uint64_t addr) {
		mnemonic = ".byte";
		std::stringstream ss;
		ss << std::hex << +data;
		operands = ss.str();
		this->addr = addr;
		in.id = 0;
	}
	vins(const std::string s, uint64_t addr);

	int size() const {
		if (in.id != 0)
			return in.size;
		return 1;
	}

	friend std::ostream& operator<<(std::ostream& os, const vins &b) {
		if (b.label.length()) {
			os << b.label << ": ";
		}
		os << b.mnemonic << ' ';
		for (int i = 0; i < b.operands.length(); ++i) {
			char c = b.operands[i];
			if (c == '%') {
				++i;
				switch (b.operands[i]) {
				case 'm':
					os << b.target_label;
				}
			}
			else {
				os << c;
			}
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

std::list<vins> disassemble(const ELFIO::elfio& reader);

void dump_text(ELFIO::elfio& writer, const std::list<vins> &d);

void calculate_target(std::list<vins> &x);

void fix_address(std::list<vins> &x);

struct lifter {
	lifter(const ELFIO::elfio& reader);

	void construct_labels();

	std::list<vins> instructions;

	const ELFIO::elfio& reader;
	ELFIO::section *sym_sec;
	ELFIO::section *rel_sec;
	ELFIO::section *text_sec;
};
