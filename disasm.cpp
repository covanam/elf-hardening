#include <string>
#include <capstone/capstone.h>
#include <tuple>
#include <list>
#include <vector>
#include <elfio/elfio.hpp>
#include "disasm.h"
#include <keystone/keystone.h>
#include <keystone/arm.h>
#include <sstream>
#include <exception>
#include <cassert>
#include <cctype>
#include <map>
#include <numeric>

using namespace ELFIO;

static bool is_jump(const cs_insn& in, const cs_detail& detail);
static bool is_call(const cs_detail& detail);
static bool can_fall_through(const cs_insn& in, const cs_detail& detail);
static void add_target_labels(
	std::list<vins>& instructions,
	const std::map<uint64_t, uint64_t>&);
static bool calculate_target_address(
	const cs_insn *in,
	const cs_detail *detail,
	uint64_t *addr);

class capstone {
public:
	using iterator = cs_insn*;
	capstone(const uint8_t *data, int size, uint64_t addr) {
		csh handle;

		if (cs_open(CS_ARCH_ARM, (cs_mode)(CS_MODE_THUMB|CS_MODE_MCLASS), &handle) != CS_ERR_OK) {
			throw std::runtime_error("cd_open() failed");
		}
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		if (size)
			count = cs_disasm(handle, data, size, addr, 0, &insn);
		else
			count = cs_disasm(handle, data, 8, addr, 1, &insn);

		cs_close(&handle);
	}

	cs_insn& operator[](size_t n) { return insn[n]; };
	size_t size() const { return count; }

	iterator begin() { return insn; }
	iterator end() { return insn + count; }

	~capstone() { cs_free(insn, count); }
private:
	cs_insn *insn;
	size_t count;
};

static std::list<vins> disassemble(const ELFIO::elfio& reader) {
	std::list<vins> ret;

	std::map<uint64_t, uint64_t> target_addr_map;

	ELFIO::section *text = nullptr, *symtab;
	for (int i = 0; i < reader.sections.size(); ++i) {
		if (reader.sections[i]->get_name() == ".text") {
			text = reader.sections[i];
		} else if (reader.sections[i]->get_type() == SHT_SYMTAB) {
			symtab = reader.sections[i];
		}
	}

	symbol_section_accessor symbols(reader, symtab);

	struct region {
		bool is_data;
		Elf64_Addr offset;
		Elf_Xword size;
	};
	std::list<region> regions;

	for (unsigned int i = 1; i < symbols.get_symbols_num(); ++i ) {
		std::string name;
		Elf64_Addr value;
		Elf_Xword size;
		unsigned char bind;
		unsigned char type;
		Elf_Half section_index;
		unsigned char other;

		symbols.get_symbol(i, name, value, size, bind,
		type, section_index, other);

		if (section_index != text->get_index())
			continue;

		/* gcc use $t and $d symbols to mark instructions and data */
		if (name == "$d") {
			regions.back().size = value - regions.back().offset;
			regions.push_back(region{true, value, 0});
		} else if (name == "$t") {
			regions.back().size = value - regions.back().offset;
			regions.push_back(region{false, value, 0});
		}
	}

	regions.back().size = text->get_size() - regions.back().offset; 

	for (const region &r : regions) {
		const uint8_t *data = (const uint8_t *)text->get_data() + r.offset;
		if (r.is_data) {
			for (unsigned i = 0; i < r.size; ++i) {
				ret.push_back(vins(data[i], r.offset + i));
			}
		}
		else {
			capstone disasm(data, r.size, r.offset);
			for (cs_insn& csin : disasm) {
				uint64_t addr;
				ret.push_back(vins(csin));
				if (calculate_target_address(&csin, csin.detail, &addr)) {
					target_addr_map.insert({csin.address, addr});
				}
			}
		}
	}

	add_target_labels(ret, target_addr_map);

	return ret;
}

std::vector<uint8_t> assemble(const std::string &s) {
	std::vector<uint8_t> ret;
	ks_engine *ks;
	ks_err err;
	size_t count;
	unsigned char *encode;
	size_t size;

	err = ks_open(KS_ARCH_ARM, KS_MODE_THUMB, &ks);
	if (err != KS_ERR_OK) {
		goto open_fail;
	}
  
	if (ks_asm(ks, s.c_str(), 0, &encode, &size, &count) != KS_ERR_OK) {
		goto asm_fail;
	} else if (count == 0 && s.length() != 0) {
		goto asm_fail;
	} else {
		ret.assign(encode, encode + size);
	}

	// NOTE: free encode after usage to avoid leaking memory
	ks_free(encode);

	// close Keystone instance when done
	ks_close(ks);

	return ret;

asm_fail:
	err = ks_errno(ks);
	ks_close(ks);
open_fail:
	std::cout << "Trying to assemble:\n" << s;
	std::string msg = "Assembling failed: ";
	msg.append(ks_strerror(err));
	throw std::runtime_error(msg);
}

static int32_t get_imm(const cs_detail *detail) {
	for (int i = 0; i < detail->arm.op_count; ++i) {
		if (detail->arm.operands[i].type == ARM_OP_IMM) {
			return detail->arm.operands[i].imm;
		}
	}
	assert(0); // this should only be called when it is known there is imm
	return 0;
}

static bool calculate_target_address(
	const cs_insn *in,
	const cs_detail *detail,
	uint64_t *addr)
{
	// what about things like add r0, pc, #8?

	for (int i = 0; i < detail->groups_count; ++i) {
		if (detail->groups[i] == ARM_GRP_BRANCH_RELATIVE) {
			*addr = get_imm(detail);
			return true;
		}
	}

	if (in->id == ARM_INS_ADR) {
		uint64_t pc = (in->address + 4) & ~(uint64_t)2;
		*addr = pc + get_imm(detail);
		return true;
	}

	for (int i = 0; i < detail->arm.op_count; ++i) {
		const cs_arm_op &op = detail->arm.operands[i];
		if (op.type == ARM_OP_MEM) {
			if (op.mem.base == ARM_REG_PC) {
				uint64_t pc = (in->address + 4) & ~(uint64_t)2;
				*addr = pc + op.mem.disp;
				return true;
			}
		}
	}

	return false;
}

static std::vector<vreg> extract_registers(std::string& operands) {
	std::vector<vreg> regs;

	for (int i = 0; i < operands.length(); ++i) {
		vreg r;
		if (!operands.compare(i, 3, "r10", 3) ||
		    !operands.compare(i, 2, "sl", 2))
			r = vreg(10); 
		else if (!operands.compare(i, 3, "r11", 3) ||
		         !operands.compare(i, 2, "fp", 2))
			r = vreg(11);
		else if (!operands.compare(i, 3, "r12", 3) ||
		         !operands.compare(i, 2, "ip", 2))
			r = vreg(12);
		else if (!operands.compare(i, 3, "r13", 3) ||
		         !operands.compare(i, 2, "sp", 2))
			r = vreg(13);
		else if (!operands.compare(i, 3, "r14", 3) ||
		         !operands.compare(i, 2, "lr", 2))
			r = vreg(14);
		else if (!operands.compare(i, 3, "r15", 3) ||
		         !operands.compare(i, 2, "pc", 2))
			r = vreg(15);
		else if (!operands.compare(i, 2, "r0", 2))
			r = vreg(0);
		else if (!operands.compare(i, 2, "r1", 2))
			r = vreg(1);
		else if (!operands.compare(i, 2, "r2", 2))
			r = vreg(2);
		else if (!operands.compare(i, 2, "r3", 2))
			r = vreg(3);
		else if (!operands.compare(i, 2, "r4", 2))
			r = vreg(4);
		else if (!operands.compare(i, 2, "r5", 2))
			r = vreg(5);
		else if (!operands.compare(i, 2, "r6", 2))
			r = vreg(6);
		else if (!operands.compare(i, 2, "r7", 2))
			r = vreg(7);
		else if (!operands.compare(i, 2, "r8", 2))
			r = vreg(8);
		else if (!operands.compare(i, 2, "r9", 2) ||
			 !operands.compare(i, 2, "sb", 2) ||
			 !operands.compare(i, 2, "tr", 2))
			r = vreg(9);
		else continue;

		if (i && 'a' <= operands[i - 1] && operands[i - 1] <= 'z')
			continue;

		int num_char;
		if (operands[i] == 'r' && r.num > 9)
			num_char = 3;
		else num_char = 2;

		std::string s = std::to_string(regs.size());
		int diff = s.size() + 1 - num_char;
		if (diff > 0) {
			operands.insert(i, diff, '*');
			operands[i] = '%';
			operands.replace(i + 1, s.size(), s);
		}
		else if (diff < 0) {
			operands[i] = '%';
			operands.replace(i + 1, s.size(), s);
			operands.replace(i + 1 + s.size(), -diff, -diff, ' ');
		}
		else {
			operands[i] = '%';
			operands.replace(i + 1, s.size(), s);
		}

		regs.push_back(r);
	}

	return regs;
}

static int capstone_id_to_ours(unsigned int cs_id) {
	switch (cs_id) {
		case ARM_REG_R0: return 0;
		case ARM_REG_R1: return 1;
		case ARM_REG_R2: return 2;
		case ARM_REG_R3: return 3;
		case ARM_REG_R4: return 4;
		case ARM_REG_R5: return 5;
		case ARM_REG_R6: return 6;
		case ARM_REG_R7: return 7;
		case ARM_REG_R8: return 8;
		case ARM_REG_R9: return 9;
		case ARM_REG_R10: return 10;
		case ARM_REG_R11: return 11;
		case ARM_REG_R12: return 12;
		case ARM_REG_R13: return 13;
		case ARM_REG_R14: return 14;
		case ARM_REG_R15: return 15;
		default:
			return -1;
	}
}

static void get_write_read_registers(
	cs_insn in,
	std::vector<vreg>& regs,
	std::vector<unsigned>& write,
	std::vector<unsigned>& read
) {
	int idx = 0;
	if (0 == regs.size())
		goto implicit_registers;
	for (int i = 0; i < in.detail->arm.op_count; ++i) {
		cs_arm_op op = in.detail->arm.operands[i];
		if (op.type == ARM_OP_REG) {
			assert(op.access != CS_AC_INVALID);
			if (op.access & CS_AC_READ)
				read.push_back(idx);
			if (op.access & CS_AC_WRITE)
				write.push_back(idx);
			if (++idx == regs.size())
				return;
		}
		else if (op.type == ARM_OP_MEM) {
			if (op.mem.base) {
				read.push_back(idx);
				if (in.detail->arm.writeback)
					write.push_back(idx);
				if (++idx == regs.size())
					return;
			}
			if (op.mem.index) {
				read.push_back(idx);
				if (in.detail->arm.writeback)
					write.push_back(idx);
				if (++idx == regs.size())
					return;
			}

			assert(!(op.mem.base && op.mem.index &&
			         in.detail->arm.writeback));
		}
	}

implicit_registers:
	for (int i = 0; i < in.detail->regs_read_count; ++i) {
		int ins_id = capstone_id_to_ours(in.detail->regs_read[i]);
		if (ins_id == -1)
			continue;

		regs.push_back(vreg(ins_id));
		read.push_back(regs.size() - 1);
	}
	for (int i = 0; i < in.detail->regs_write_count; ++i) {
		int ins_id = capstone_id_to_ours(in.detail->regs_write[i]);
		if (ins_id == -1)
			continue;

		regs.push_back(vreg(ins_id));
		write.push_back(regs.size() - 1);
	}
}

vins::vins(const cs_insn &in) {
	this->addr = in.address;

	mnemonic = in.mnemonic;
	operands = in.op_str;

	uint64_t dum;
	if (calculate_target_address(&in, in.detail, &dum)) {
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

	int imm_start = operands.find('#');
	if (imm_start != std::string::npos) {
		++imm_start;
		size_t imm_len;
		this->_imm = std::stoll(operands.substr(imm_start), &imm_len, 0);
		operands.replace(imm_start, imm_len, "%i");
	}

	_is_jump = ::is_jump(in, *in.detail);
	_is_call = ::is_call(*in.detail);
	_can_fall_through = ::can_fall_through(in, *in.detail);

	_size = in.size;

	this->regs = extract_registers(operands);
	get_write_read_registers(in, regs, gen, use);

	switch (in.id) {
		//#TODO this should be in the assembler
		case ARM_INS_ADC:
		case ARM_INS_ADD:
		case ARM_INS_AND:
		case ARM_INS_BIC:
		case ARM_INS_EOR:
		case ARM_INS_ORR:
		case ARM_INS_SBC:
		case ARM_INS_SUB:
			if (
				in.detail->arm.op_count == 2 &&
				in.detail->arm.operands[0].type == ARM_OP_REG &&
				in.detail->arm.operands[1].type == ARM_OP_REG
			) {
				operands = "%0, %0, %1";
			}
			break;
		case ARM_INS_MUL:
			if (mnemonic == "muls") //#TODO are we sure flags are not used?
				mnemonic.resize(3);
	}

	switch (in.detail->arm.cc) {
		case ARM_CC_EQ: cond = "eq"; break;
		case ARM_CC_NE: cond = "ne"; break;
		case ARM_CC_HS: cond = "hs"; break;
		case ARM_CC_LO: cond = "lo"; break;
		case ARM_CC_MI: cond = "mi"; break;
		case ARM_CC_PL: cond = "pl"; break;
		case ARM_CC_VS: cond = "vs"; break;
		case ARM_CC_VC: cond = "vc"; break;
		case ARM_CC_HI: cond = "hi"; break;
		case ARM_CC_LS: cond = "ls"; break;
		case ARM_CC_GE: cond = "ge"; break;
		case ARM_CC_LT: cond = "lt"; break;
		case ARM_CC_GT: cond = "gt"; break;
		case ARM_CC_LE: cond = "le"; break;
		case ARM_CC_AL: break;
		default:
			std::cerr << "Instruction " << in.mnemonic << ' ' << in.op_str;
			std::cerr << " has invalid condition: " << in.detail->arm.cc << '\n';
			assert(0);
	}
}

vins::vins(uint8_t data, uint64_t addr) {
	mnemonic = ".byte";
	std::stringstream ss;
	ss << "0x" << std::hex << +data;
	operands = ss.str();
	this->addr = addr;
	_is_call = false;
	_is_jump = false;
	_can_fall_through = false;
	_size = 1;
}

vins vins::ins_cmp(vreg r, int imm) {
	vins in;
	in.addr = std::numeric_limits<uint64_t>::max();
	in.mnemonic = "cmp";
	in.operands = "%0, #" + std::to_string(imm);
	in.regs.push_back(r);
	in.use.push_back(0);
	in._is_call = false;
	in._is_jump = false;
	in._can_fall_through = true;
	in._size = 0;
	return in;
}

vins vins::ins_b(const char *condition, const char *label) {
	vins in;
	in.addr = std::numeric_limits<uint64_t>::max();
	in.mnemonic = std::string("b") + condition;
	in.operands = "%m";
	in.target_label = label;
	in._is_call = false;
	in._is_jump = true;
	in._can_fall_through = (condition[0] != '\0');
	in._size = 0;
	return in;
}

vins vins::ins_add(vreg d, vreg r1, vreg r2) {
	vins in;
	in.addr = std::numeric_limits<uint64_t>::max();
	in.mnemonic = "add";
	in.operands = "%0, %1, %2";
	in._is_call = false;
	in._is_jump = false;
	in._can_fall_through = true;
	in._size = 0;
	in.regs = {d, r1, r2};
	in.use = {1, 2};
	in.gen = {0};

	return in;
}

vins vins::ins_add(vreg d, vreg r, int imm) {
	vins in;
	in.addr = std::numeric_limits<uint64_t>::max();
	in.mnemonic = "add";
	in.operands = "%0, %1, #" + std::to_string(imm);
	in._is_call = false;
	in._is_jump = false;
	in._can_fall_through = true;
	in._size = 0;
	in.regs = {d, r};
	in.use = {1};
	in.gen = {0};

	return in;
}

vins vins::ins_sub(vreg d, vreg r, int imm) {
	vins in;
	in.addr = std::numeric_limits<uint64_t>::max();
	in.mnemonic = "sub";
	in.operands = "%0, %1, #" + std::to_string(imm);
	in._is_call = false;
	in._is_jump = false;
	in._can_fall_through = true;
	in._size = 0;
	in.regs = {d, r};
	in.use = {1};
	in.gen = {0};

	return in;
}

vins vins::ins_mov(vreg r, int imm) {
	vins in;
	in.addr = std::numeric_limits<uint64_t>::max();
	in.mnemonic = "mov";
	in.operands = "%0, #" + std::to_string(imm);
	in._is_call = false;
	in._is_jump = false;
	in._can_fall_through = true;
	in._size = 0;
	in.regs = {r};
	in.gen = {0};

	return in;
}

vins vins::ins_mov(vreg d, vreg s) {
	vins in;
	in.addr = std::numeric_limits<uint64_t>::max();
	in.mnemonic = "mov";
	in.operands = "%0, %1";
	in._is_call = false;
	in._is_jump = false;
	in._can_fall_through = true;
	in._size = 0;
	in.regs = {d, s};
	in.gen = {0};
	in.use = {1};

	return in;
}

vins vins::ins_str(vreg data, vreg addr, int offset) {
	vins in;
	in.addr = std::numeric_limits<uint64_t>::max();
	in.mnemonic = "str";
	in.operands = "%0, [%1, #" + std::to_string(offset) + "]";
	in._is_call = false;
	in._is_jump = false;
	in._can_fall_through = true;
	in._size = 0;
	in.regs = {data, addr};
	in.use = {0, 1};

	return in;
}

vins vins::ins_ldr(vreg data, vreg addr, int offset) {
	vins in;
	in.addr = std::numeric_limits<uint64_t>::max();
	in.mnemonic = "ldr";
	in.operands = "%0, [%1, #" + std::to_string(offset) + "]";
	in._is_call = false;
	in._is_jump = false;
	in._can_fall_through = true;
	in._size = 0;
	in.regs = {data, addr};
	in.use = {1};
	in.gen = {0};

	return in;
}

vins vins::ins_str(vreg data, const std::string& label) {
	vins in;
	in.addr = std::numeric_limits<uint64_t>::max();
	in.mnemonic = "str";
	in.operands = "%0, %m";
	in.target_label = label;
	in._is_call = false;
	in._is_jump = false;
	in._can_fall_through = true;
	in._size = 0;
	in.regs = {data};
	in.use = {0};

	return in;
}
vins vins::ins_ldr(vreg data, const std::string& label) {
	vins in;
	in.addr = std::numeric_limits<uint64_t>::max();
	in.mnemonic = "ldr";
	in.operands = "%0, %m";
	in.target_label = label;
	in._is_call = false;
	in._is_jump = false;
	in._can_fall_through = true;
	in._size = 0;
	in.regs = {data};
	in.gen = {0};

	return in;
}

vins vins::ins_return() {
	vins in;
	in.addr = std::numeric_limits<uint64_t>::max();
	in.mnemonic = "bx";
	in.operands = "%0";
	in._is_call = false;
	in._is_jump = true;
	in._can_fall_through = false;
	in._size = 0;
	in.regs = {vreg(14)};
	in.use = {0};

	return in;
}

vins vins::ins_arm_it(const char* cond) {
	vins in;
	in.addr = std::numeric_limits<uint64_t>::max();
	in.mnemonic = "it";
	in.operands = cond;
	in._is_call = false;
	in._is_jump = false;
	in._can_fall_through = true;
	in._size = 0;

	return in;
}

vins vins::data_word(int data) {
	vins in;
	in.addr = std::numeric_limits<uint64_t>::max();
	in.mnemonic = ".word";
	in.operands = std::to_string(data);
	in._is_call = false;
	in._is_jump = false;
	in._can_fall_through = false;
	in._size = 0;

	return in;
}


template<class list> vins vins::push_second_stack(const list& regs) {
	vins in;
	in.addr = std::numeric_limits<uint64_t>::max();

	if (regs.size() == 1) {
		in.mnemonic = "str";
		in.operands = "%0, [fp], #4";
	}
	else {
		in.mnemonic = "stmia";
		std::stringstream ss;
		ss << "fp!, {" << *regs.begin();
		for (auto r = std::next(regs.begin()); r != regs.end(); ++r) {
			ss << ", " << *r;
		}
		ss << '}';
		in.operands = ss.str();
	}

	in._is_call = false;
	in._is_jump = false;
	in._can_fall_through = true;
	in._size = 0;
	in.regs = regs;
	in.use = std::vector<unsigned>(regs.size());
	std::iota(in.use.begin(), in.use.end(), 0);

	return in;
}

template<class list> vins vins::pop_second_stack(const list& regs) {
	vins in;
	in.addr = std::numeric_limits<uint64_t>::max();

	if (regs.size() == 1) {
		in.mnemonic = "ldr";
		in.operands = "%0, [fp, #-4]!";
	}
	else {
		in.mnemonic = "ldmdb";
		std::stringstream ss;
		ss << "fp!, {" << *regs.begin();
		for (auto r = std::next(regs.begin()); r != regs.end(); ++r) {
			ss << ", " << *r;
		}
		ss << '}';
		in.operands = ss.str();
	}

	in._is_call = false;
	in._is_jump = false;
	in._can_fall_through = true;
	in._size = 0;
	in.regs = regs;
	in.gen = std::vector<unsigned>(regs.size());
	std::iota(in.gen.begin(), in.gen.end(), 0);

	return in;
}

template vins vins::push_second_stack<std::vector<vreg>>(const std::vector<vreg>& regs);
template vins vins::pop_second_stack<std::vector<vreg>>(const std::vector<vreg>& regs);
template vins vins::push_second_stack<std::initializer_list<vreg>>(const std::initializer_list<vreg>& regs);
template vins vins::pop_second_stack<std::initializer_list<vreg>>(const std::initializer_list<vreg>& regs);

template<class list> vins vins::stmia(vreg addr, const list& regs) {
	vins in;
	in.addr = std::numeric_limits<uint64_t>::max();

	if (regs.size() == 1) {
		in.mnemonic = "str";
		in.operands = "%1, [%0], #4";
	}
	else {
		in.mnemonic = "stmia";
		std::stringstream ss;
		ss << "%0!, {" << *regs.begin();
		for (auto r = std::next(regs.begin()); r != regs.end(); ++r) {
			ss << ", " << *r;
		}
		ss << '}';
		in.operands = ss.str();
	}

	in._is_call = false;
	in._is_jump = false;
	in._can_fall_through = true;
	in._size = 0;
	in.regs.push_back(addr);
	in.regs.insert(in.regs.end(), regs.begin(), regs.end());
	in.use = std::vector<unsigned>(in.regs.size());
	std::iota(in.use.begin(), in.use.end(), 0);

	return in;
}

template<class list> vins vins::ldmdb(vreg addr, const list& regs) {
	vins in;
	in.addr = std::numeric_limits<uint64_t>::max();

	if (regs.size() == 1) {
		in.mnemonic = "ldr";
		in.operands = "%1, [%0, #-4]!";
	}
	else {
		in.mnemonic = "ldmdb";
		std::stringstream ss;
		ss << "%0!, {" << *regs.begin();
		for (auto r = std::next(regs.begin()); r != regs.end(); ++r) {
			ss << ", " << *r;
		}
		ss << '}';
		in.operands = ss.str();
	}

	in._is_call = false;
	in._is_jump = false;
	in._can_fall_through = true;
	in._size = 0;
	in.regs.push_back(addr);
	in.regs.insert(in.regs.end(), regs.begin(), regs.end());
	in.gen = std::vector<unsigned>(regs.size());
	std::iota(in.gen.begin(), in.gen.end(), 1);
	in.use = {0};

	return in;
}

template vins vins::stmia<std::vector<vreg>>(vreg addr, const std::vector<vreg>& regs);
template vins vins::ldmdb<std::vector<vreg>>(vreg addr, const std::vector<vreg>& regs);

bool vins::is_pseudo() const {
	return this->mnemonic == "pseudo";
}

vins vins::function_entry() {
	vins in;
	in.addr = std::numeric_limits<uint64_t>::max();
	in.mnemonic = "pseudo";
	in.operands = "func_entry";

	in.regs = {vreg(0), vreg(1), vreg(2), vreg(3), vreg(4), vreg(5), vreg(6),
		vreg(7), vreg(8), vreg(9), vreg(10), vreg(11), vreg(13), vreg(14),
		vreg(15)};
	in.gen = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};

	in._is_call = false;
	in._is_jump = false;
	in._can_fall_through = true;
	in._size = 0;
	return in;
}

vins vins::function_exit() {
	vins in;
	in.addr = std::numeric_limits<uint64_t>::max();
	in.mnemonic = "pseudo";
	in.operands = "func_exit";

	in.regs = {vreg(0), vreg(1), vreg(2), vreg(3), vreg(4), vreg(5), vreg(6),
		vreg(7), vreg(8), vreg(9), vreg(10), vreg(11), vreg(13), vreg(14),
		vreg(15)};
	in.use = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};

	in._is_call = false;
	in._is_jump = false;
	in._can_fall_through = true;
	in._size = 0;
	return in;
}

bool vins::is_data() const {
	return
		mnemonic == ".word" ||
		mnemonic == ".short" ||
		mnemonic == ".byte";
}

static bool is_jump(const cs_insn& in, const cs_detail& detail) {
	for (int i = 0; i < detail.groups_count; ++i) {
		if (detail.groups[i] == CS_GRP_JUMP) {
			return true;
		}
	}

	for (int i = 0; i < detail.arm.op_count; ++i) {
		cs_arm_op op = detail.arm.operands[i];
		if (
			op.type == ARM_OP_REG &&
			op.access & CS_AC_WRITE &&
			op.reg == ARM_REG_PC
		) {
			return true;
		}
	}

	return false;
}

static bool is_call(const cs_detail& detail) {
	for (int i = 0; i < detail.groups_count; ++i) {
		if (detail.groups[i] == CS_GRP_CALL) {
			return true;
		}
	}

	return false;
}

static bool can_fall_through(const cs_insn& in, const cs_detail& detail) {
	if (detail.arm.cc != ARM_CC_AL)
		return true;

	if (in.id == ARM_INS_CBNZ || in.id == ARM_INS_CBZ)
		return true;

	if (is_jump(in, detail))
		return false;

	return true;
}

bool vins::is_function_return() const {
	// #TODO: are we sure this is always true?
	return is_jump() && target_label.empty() && !is_call();
}

int vins::size() const {
	assert(_size);
	return _size;
}

bool vins::is_local_call() const {
	return is_call() && !target_label.empty() && target_label[0] != '.';
}

void vins::transfer_label(vins& in) {
	in.label = std::move(this->label);
	label = std::string();

	in.sym = std::move(this->sym);
	this->sym.clear();
}

std::ostream& operator<<(std::ostream& os, vreg r) {
	switch(r.num) {
		case 9:
			return os << "sb";
		case 10:
			return os << "sl";
		case 11:
			return os << "fp";
		case 12:
			return os << "ip";
		case 14:
			return os << "lr";
		case 13:
			return os << "sp";
		case 15:
			return os << "pc";
		default:
			if (r.spill_slot >= 0)
				return os << 's' << r.spill_slot;
			if (r.num < 9)
				return os << 'r' << r.num;
			return os << 'v' << r.num - 16;
	}
}

std::ostream& operator<<(std::ostream& os, const vins &b) {
	if (b.label.length()) {
		os << b.label << ": ";
	} else if (b.rel >= 0) {
		if (b.label.empty())
			os << ".reloc" << b.addr << ": "; // b.addr should be unique
		else
			os << b.target_label;
	}
	os << b.mnemonic << ' ';
	for (int i = 0; i < b.operands.length();) {
		char c = b.operands[i];
		if (c == '%') {
			++i;
			if (b.operands[i] == 'm') {
				if (b.rel >= 0) {
					if (b.label.empty())
						os << ".reloc" << b.addr;
					else
						os << b.label;
				} else {
					os << b.target_label;
				}
				++i;
			} else if (b.operands[i] == 'i') {
				os << b._imm;
				++i;
			} else {
				int reg_num = 0;
				while (isdigit(b.operands[i])) {
					reg_num = (b.operands[i] - '0') + 10 * reg_num;
					++i;
				}
				os << b.regs[reg_num];
			}
		}
		else {
			os << c;
			++i;
		}
	}
	return os;
}

struct addr_update {
	uint64_t old_addr;
	uint64_t new_addr;
};

static void update_symbol_table(section *s, std::list<vins>& ins) {
	Elf32_Sym* sym = (Elf32_Sym*)s->get_data();

	for (vins& in : ins) {
		for (int s : in.sym) {
			sym[s].st_value = in.addr;

			if (ELF_ST_TYPE(sym[s].st_info) == STT_FUNC)
				sym[s].st_value |= 1;
		}
	}
}

static void update_relocation_table(section *s, std::list<vins>& ins, 
	const elfio& elf_file
) {
	if (!s)
		return;

	Elf32_Rel* rel = (Elf32_Rel*)s->get_data();

	for (vins& in : ins) {
		if (in.rel >= 0) {
			rel[in.rel].r_offset = in.addr;
		}
	}
}

static void update_addr(
	std::list<vins>& inl,
	const std::vector<uint8_t>& bin
) {
	uint64_t addr = 0;
	auto vi = inl.begin();
	for (int i = 0; i < inl.size(); ++i) {
		unsigned size;

		if (vi->is_pseudo()) {
			size = 0;
		} else if (!vi->is_data()) {
			capstone disasm(&bin[addr], 0, addr);
			size = disasm[0].size;
		} else {
			if (vi->mnemonic == ".byte") {
				size = 1;
			}
			else if (vi->mnemonic == ".short") {
				size = 2;
				addr = (addr + 1) & ~(uint64_t)1;
			}
			else if ((vi->mnemonic == ".word")) {
				size = 4;
				addr = (addr + 3) & ~(uint64_t)3;
			}
			else assert(0);
		}

		vi->addr = addr;

		++vi;
		addr += size;
	}
}

static bool four_bytes_to_word(std::list<vins> &l, std::list<vins>::iterator i) {
	if ((i++)->mnemonic == ".byte" &&
		i != l.end() && i->label.empty() && (i++)->mnemonic == ".byte" &&
		i != l.end() && i->label.empty() && (i++)->mnemonic == ".byte" &&
		i != l.end() && i->label.empty() && (i)->mnemonic == ".byte"
	) {
		uint32_t data = (uint32_t)std::stoi(i->operands, nullptr, 16) << 24;
		l.erase(i--);
		data |= (uint32_t)std::stoi(i->operands, nullptr, 16) << 16;
		l.erase(i--);
		data |= (uint32_t)std::stoi(i->operands, nullptr, 16) << 8;
		l.erase(i--);
		data |= (uint32_t)std::stoi(i->operands, nullptr, 16);
		i->mnemonic = ".word";
		i->operands = std::to_string(data);
		return true;
	}
	return false;
}

static bool two_bytes_to_short(std::list<vins> &l, std::list<vins>::iterator i) {
	if ((i++)->mnemonic == ".byte" &&
		i != l.end() && i->label.empty() && i->mnemonic == ".byte"
	) {
		uint16_t data = (uint16_t)std::stoi(i->operands, nullptr, 16) << 8;
		l.erase(i--);
		data |= (uint16_t)std::stoi(i->operands, nullptr, 16);
		i->mnemonic = ".short";
		i->operands = std::to_string(data);
		return true;
	}
	return false;
}

static bool two_short_to_word(std::list<vins> &l, std::list<vins>::iterator i) {
	if ((i++)->mnemonic == ".short" &&
		i != l.end() && i->label.empty() && i->mnemonic == ".short") {
		uint32_t data = (uint32_t)std::stoi(i->operands, nullptr, 16) << 16;
		l.erase(i--);
		data |= (uint32_t)std::stoi(i->operands, nullptr, 16);
		i->mnemonic = ".word";
		i->operands = std::to_string(data);
		return true;
	}
	return false;
}

static void merge_small_data(std::list<vins> &ins) {
	for (auto i = ins.begin(); i != ins.end(); ++i) {
		four_bytes_to_word(ins, i) ||
		two_bytes_to_short(ins, i) ||
		two_short_to_word(ins, i);
	}
}

static void remove_nops(std::list<vins>& il) {
	/* nops are used for alignment, which is also done by keystone. So it
	   should be fine to remove them */
	for (auto i = il.begin(); i != il.end();) {
		auto next = std::next(i);
		if (i->mnemonic.rfind("nop", 0) == 0 && i->label.empty())
			il.erase(i);
		i = next;
	}
}

static void remove_it(std::list<vins>& il) {
	for (auto i = il.begin(); i != il.end();) {
		auto next = std::next(i);
		if (i->mnemonic.rfind("it", 0) == 0) {
			i->transfer_label(*next);
			il.erase(i);
		}
		i = next;
	}
}

void lifter::add_second_stack_addresses() {
	std::string sstack_label = ".second_stack_0";
	int label_count = 1;

	add_second_stack_address(instructions.end(), sstack_label);

	for (auto in = instructions.rbegin(); in != --instructions.rend(); ++in) {
		if (in->is_pseudo() && in->operands == "func_entry") {
			sstack_label = ".second_stack_" + std::to_string(label_count);
			add_second_stack_address(--in.base(), sstack_label);
			++label_count;
		}

		if (in->target_label == ".second_stack")
			in->target_label = sstack_label;
	}
}

void lifter::save(std::string file) {
	if(!text_sec) {
		if (!reader.save(file))
			throw std::runtime_error("Failed to write to " + file);
	}

	add_second_stack_addresses();

	for (auto in = instructions.begin(); in != instructions.end(); ++in) {
		if (in->cond.size() && in->mnemonic.rfind("b", 0) != 0) {
			vins tmp = vins::ins_arm_it(in->cond.c_str());
			in->transfer_label(tmp);
			instructions.insert(in, std::move(tmp));
		}
	}

	std::stringstream assembly;

	int align = 1;
	for (const vins &b : this->instructions) {
		if (b.is_pseudo()) {
			if (false == b.label.empty())
				assembly << b.label << ": ";
			continue;
		}

		if (b.mnemonic == ".word") {
			if (align % 4)
				assembly << ".align 2\n";
			align = 4;
		}
		else if (b.mnemonic == ".short") {
			if (align % 2)
				assembly << ".align 1\n";
			align = 2;
		}
		else if (b.mnemonic == ".byte") {
			align = 1;
		}
		else if (!b.is_data()){
			align = 2;
		}
		else assert(0);

		assembly << b << '\n';
	}
	std::vector<uint8_t> bin = assemble(assembly.str());
	text_sec->set_data((const char *)&bin[0], bin.size());

	update_addr(instructions, bin);

	for (int i = 0; i < reader.sections.size(); ++i) {
		if (reader.sections[i]->get_name() == ".text") {
			update_symbol_table(sym_sec, instructions);
			break;
		}
	}

	update_relocation_table(rel_sec, instructions, reader);

	if (!reader.save(file)) {
		throw std::runtime_error("Failed to write to " + file);
	}
}

static int is_relocatable(uint64_t addr, const section *rel) {
	if (!rel)
		return -1;

	Elf32_Rel *reltab = (Elf32_Rel *)rel->get_data();

	for (int i = 0; i < rel->get_size() / rel->get_entry_size(); ++i) {
		if (reltab[i].r_offset == addr) {
			return i;
		}
	}

	return -1;
}

static void remove_fake_labels(
	std::list<vins>& instructions,
	const ELFIO::section *rel_sec
) {
	for (vins& in : instructions) {
		in.rel = is_relocatable(in.addr, rel_sec);
		if (in.rel < 0)
			continue;

		if (in.is_data())
			continue;
		
		bool others_jump_here = false;
		for (vins& inn : instructions) {
			if (&in == &inn)
				continue;
			if (inn.is_jump() && inn.target_label == in.label) {
				others_jump_here = true;
				break;
			}
		}

		in.target_label.clear();
		if (!others_jump_here && in.label[0] == '.')
			in.label.clear();
	}
}

static void transform_cbnz_cbz(std::list<vins>& instructions) {
	for (auto it = instructions.begin(); it != instructions.end();) {
		auto next = std::next(it);
		if (it->mnemonic == "cbnz") {
			vins& cbnz = *it;
			vins temp = vins::ins_cmp(cbnz.regs[0], 0);
			it->transfer_label(temp);
			instructions.insert(it, std::move(temp));
			temp = vins::ins_b("ne", cbnz.target_label.c_str());
			instructions.insert(it, std::move(temp));
			instructions.erase(it);
		}
		else if (it->mnemonic == "cbz") {
			vins& cbnz = *it;
			vins temp = vins::ins_cmp(cbnz.regs[0], 0);
			it->transfer_label(temp);
			instructions.insert(it, std::move(temp));
			temp = vins::ins_b("eq", cbnz.target_label.c_str());
			instructions.insert(it, std::move(temp));
			instructions.erase(it);
		}
		it = next;
	}
}

void lifter::get_function_name() {
	symbol_section_accessor symbols(reader, sym_sec);

	for (unsigned int i = 1; i < symbols.get_symbols_num(); ++i) {
		std::string name;
		Elf64_Addr value;
		Elf_Xword size;
		unsigned char bind;
		unsigned char type;
		Elf_Half section_index;
		unsigned char other;
		symbols.get_symbol(
			i,
			name,
			value,
			size,
			bind,
			type,
			section_index,
			other);

		if (text_sec != reader.sections[section_index])
			continue;
		
		if (type != STT_FUNC)
			continue;

		if (bind != STB_GLOBAL && bind != STB_WEAK)
			continue;

		functions.insert(name);
	}
}

static void add_call_registers(std::list<vins>& instructions) {
	for (auto& in : instructions) {
		if (in.is_call() && !in.is_local_call()) {
			in.regs = {vreg(0), vreg(1), vreg(2), vreg(3), vreg(0),
				vreg(1), vreg(2), vreg(3)};
			in.use = {0, 1, 2, 3};
			in.gen = {4, 5, 6, 7};
		}
	}
}

void lifter::add_second_stack_address(
	std::list<vins>::iterator pos,
	const std::string& label
) {
	string_section_accessor str_writer(str_sec);
	symbol_section_accessor sym_writer(reader, sym_sec);
	relocation_section_accessor rel_writer(reader, rel_sec);

	Elf_Word sym = sym_writer.add_symbol(
		str_writer,
		"__second_stack",
		0,
		0,
		ELF_ST_INFO(STB_GLOBAL, STT_OBJECT),
		0,
		SHN_UNDEF);

	rel_writer.add_entry(0, sym, 2); // #define R_ARM_ABS32 2

	vins second_sp = vins::data_word(0);
	second_sp.label = label;
	second_sp.rel = rel_writer.get_entries_num() - 1;

	instructions.insert(pos, std::move(second_sp));
}

bool lifter::load(std::string file) {
	if (!reader.load(file))
		return false;

	sym_sec = rel_sec = text_sec = str_sec = nullptr;

	int text_idx, symtab_idx;
	for (int i = 0; i < reader.sections.size(); ++i) {
		section* psec = reader.sections[i];
		if (psec->get_type() == SHT_SYMTAB) {
			sym_sec = psec;
			symtab_idx = i;
		}
		else if (reader.sections[i]->get_name() == ".strtab") {
			str_sec = psec;
		}
		else if (reader.sections[i]->get_name() == ".rel.text") {
			rel_sec = psec;
		}
		else if (reader.sections[i]->get_name() == ".text") {
			text_sec = psec;
			text_idx = i;
		}
	}

	if (!text_sec)
		return true;

	if (rel_sec == nullptr) {
		rel_sec = reader.sections.add(".rel.text");
		rel_sec->set_type(SHT_REL);
		//rel_sec->set_flags(SHF_ALLOC | SHF_EXECINSTR);
		rel_sec->set_info(text_idx);
		rel_sec->set_link(symtab_idx);
		rel_sec->set_entry_size(sizeof(struct Elf32_Rel));
	}

	assert(str_sec && sym_sec && rel_sec);


	get_function_name();
	instructions = disassemble(reader);
	add_labels_from_symbol_table();
	remove_fake_labels(instructions, rel_sec);
	add_call_registers(instructions);
	merge_small_data(instructions);
	remove_nops(instructions);
	transform_cbnz_cbz(instructions);
	remove_it(instructions);

	return true;
}

void lifter::add_labels_from_symbol_table() {
	symbol_section_accessor symbols(reader, sym_sec);

	for (unsigned int i = 1; i < symbols.get_symbols_num(); ++i) {
		std::string name;
		Elf64_Addr value;
		Elf_Xword size;
		unsigned char bind;
		unsigned char type;
		Elf_Half section_index;
		unsigned char other;
		symbols.get_symbol(
			i,
			name,
			value,
			size,
			bind,
			type,
			section_index,
			other);

		if (text_sec != reader.sections[section_index])
			continue;

		for (vins& in : this->instructions) {
			if (type == STT_FUNC && in.addr == value - 1) {
				if (in.label.length()) {
					for (vins& inn : this->instructions) {
						if (inn.target_label == in.label)
							inn.target_label = name;
					}
				}
				in.label = name;
				in.sym.push_back(i);
			}
			else if (in.addr == value) {
				in.sym.push_back(i);
			}
		}
	}
}

static void add_target_labels(
	std::list<vins>& instructions,
	const std::map<uint64_t, uint64_t>& target_addr_map
) {
	int label_cnt = 0;

	for (vins& in : instructions) {
		uint64_t addr;

		if (in.is_data())
			continue; // data

		if (in.target_label.size() != 0)
			continue;

		std::map<uint64_t, uint64_t>::const_iterator it = target_addr_map.find(in.addr);
		if (it == target_addr_map.end())
			continue;
		
		addr = it->second;
		
		auto temp = std::find_if(instructions.begin(), instructions.end(),
			[addr](vins &t) { return addr == t.addr; });
		if (temp == instructions.end())
			continue;
	
		if (temp->label.empty()) {
			temp->label = ".L" + std::to_string(label_cnt);
			label_cnt++;
		}
		
		in.target_label = temp->label;
	}
}
