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

using namespace ELFIO;

static std::list<vins> disassemble(const uint8_t *data, int size, uint64_t addr) {
	std::list<vins> ret;
	csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_ARM, (cs_mode)(CS_MODE_THUMB|CS_MODE_MCLASS), &handle) != CS_ERR_OK) {
		throw std::runtime_error("cd_open() failed");
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	if (size)
		count = cs_disasm(handle, data, size, addr, 0, &insn);
	else
		count = cs_disasm(handle, data, 8, addr, 1, &insn);

	if (count > 0) {
		size_t j;
		ret.assign(insn, insn + count);

		cs_free(insn, count);
	} else {
		/* #TODO */
	}
	cs_close(&handle);

	return ret;
}

static std::list<vins> disassemble(const ELFIO::elfio& reader) {
	std::list<vins> ret;

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
			ret.splice(ret.end(), disassemble(data, r.size, r.offset));
		}
	}

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
			r = 10; 
		else if (!operands.compare(i, 3, "r11", 3) ||
		         !operands.compare(i, 2, "fp", 2))
			r = 11;
		else if (!operands.compare(i, 3, "r12", 3) ||
		         !operands.compare(i, 2, "ip", 2))
			r = 12;
		else if (!operands.compare(i, 3, "r14", 3) ||
		         !operands.compare(i, 2, "lr", 2))
			r = 14;
		else if (!operands.compare(i, 2, "r0", 2))
			r = 0;
		else if (!operands.compare(i, 2, "r1", 2))
			r = 1;
		else if (!operands.compare(i, 2, "r2", 2))
			r = 2;
		else if (!operands.compare(i, 2, "r3", 2))
			r = 3;
		else if (!operands.compare(i, 2, "r4", 2))
			r = 4;
		else if (!operands.compare(i, 2, "r5", 2))
			r = 5;
		else if (!operands.compare(i, 2, "r6", 2))
			r = 6;
		else if (!operands.compare(i, 2, "r7", 2))
			r = 7;
		else if (!operands.compare(i, 2, "r8", 2))
			r = 8;
		else if (!operands.compare(i, 2, "r9", 2) ||
			 !operands.compare(i, 2, "sb", 2) ||
			 !operands.compare(i, 2, "tr", 2))
			r = 9;
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
		if (op.type == ARM_OP_REG &&
		    op.reg != ARM_REG_PC &&
		    op.reg != ARM_REG_SP) {
			if (op.access & CS_AC_READ)
				read.push_back(idx);
			if (op.access & CS_AC_WRITE)
				write.push_back(idx);
			if (++idx == regs.size())
				return;
		}
		else if (op.type == ARM_OP_MEM) {
			if (op.mem.base &&
			    op.mem.base != ARM_REG_PC &&
			    op.mem.base != ARM_REG_SP) {
				read.push_back(idx);
				if (in.detail->arm.writeback)
					write.push_back(idx);
				if (++idx == regs.size())
					return;
			}
			if (op.mem.index &&
			    op.mem.index != ARM_REG_PC &&
			    op.mem.index != ARM_REG_SP) {
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
		if (in.detail->regs_read[i] == ARM_REG_PC ||
		    in.detail->regs_read[i] == ARM_REG_SP)
			continue;

		int ins_id = capstone_id_to_ours(in.detail->regs_read[i]);
		if (ins_id == -1)
			continue;

		regs.push_back(vreg(ins_id));
		read.push_back(regs.size() - 1);
	}
	for (int i = 0; i < in.detail->regs_write_count; ++i) {
		if (in.detail->regs_write[i] == ARM_REG_PC ||
		    in.detail->regs_write[i] == ARM_REG_SP)
			continue;

		int ins_id = capstone_id_to_ours(in.detail->regs_write[i]);
		if (ins_id == -1)
			continue;

		regs.push_back(vreg(ins_id));
		write.push_back(regs.size() - 1);
	}

	if (in.id == ARM_INS_BL) {
		for (int i = 0; i < 4; ++i) {
			regs.push_back(vreg(i));
			read.push_back(regs.size() - 1);
		}
		for (int i = 0; i < 2; ++i) {
			regs.push_back(vreg(i));
			write.push_back(regs.size() - 1);
		}
	}
}

vins::vins(const cs_insn &in) {
	is_original = true;
	this->in = in;
	this->addr = in.address;
	detail = *in.detail;

	mnemonic = in.mnemonic;
	operands = in.op_str;

	uint64_t dum;
	if (calculate_target_address(&in, &detail, &dum)) {
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

	this->regs = extract_registers(operands);
	get_write_read_registers(in, regs, gen, use);
}

vins::vins(uint8_t data, uint64_t addr) {
	is_original = true;
	mnemonic = ".byte";
	std::stringstream ss;
	ss << "0x" << std::hex << +data;
	operands = ss.str();
	this->addr = addr;
	in.id = 0;
}

vins::vins(const std::string s) {
	is_original = false;
	int i;
	for (i = 0; i < s.length(); ++i) {
		if (s[i] == ' ')
			break;
	}
	mnemonic = s.substr(0, i);
	operands = s.substr(i, s.length() - i);
}

bool vins::is_data() const {
	return
		mnemonic == ".word" ||
		mnemonic == ".short" ||
		mnemonic == ".byte";
}

bool vins::is_jump() const {
	assert(is_original);

	if (is_data())
		return false;

	for (int i = 0; i < detail.groups_count; ++i) {
		if (detail.groups[i] == CS_GRP_JUMP) {
			return true;
		}
	}

	if (in.id == ARM_INS_POP) {
		for (int i = 0; i < detail.arm.op_count; ++i) {
			if (detail.arm.operands[i].type == ARM_OP_REG &&
			    detail.arm.operands[i].reg == ARM_REG_PC) {
				return true;
			}
		}
	}

	return false;
}

bool vins::is_call() const {
	assert(is_original);

	if (is_data())
		return false;

	for (int i = 0; i < detail.groups_count; ++i) {
		if (detail.groups[i] == CS_GRP_CALL) {
			return true;
		}
	}

	return false;
}

bool vins::can_fall_through() const {
	if (is_data())
		return false;

	if (detail.arm.cc != ARM_CC_AL)
		return true;

	if (in.id == ARM_INS_CBNZ || in.id == ARM_INS_CBZ)
		return true;

	for (int i = 0; i < detail.groups_count; ++i) {
		if (detail.groups[i] == CS_GRP_CALL) {
			return true;
		}
	}

	if (this->is_jump())
		return false;

	return true;
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
		case 15:
			assert(0);
		default:
			return os << 'r' << r.num;
	}
}

std::ostream& operator<<(std::ostream& os, const vins &b) {
	if (b.label.length()) {
		os << b.label << ": ";
	}
	os << b.mnemonic << ' ';
	for (int i = 0; i < b.operands.length();) {
		char c = b.operands[i];
		if (c == '%') {
			++i;
			if (b.operands[i] == 'm') {
				os << b.target_label;
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
	std::cout << "; Use: ";
	for (int i = 0; i < b.use.size(); ++i)
		std::cout << b.regs[b.use[i]] << ' ';
	std::cout << "; Gen: ";
	for (int i = 0; i < b.gen.size(); ++i)
		std::cout << b.regs[b.gen[i]] << ' ';
	return os;
}

struct addr_update {
	uint64_t old_addr;
	uint64_t new_addr;
};

static void update_symbol_table(section *s, const std::vector<addr_update>& remap, int txt) {
	Elf32_Sym *symtab = (Elf32_Sym *)s->get_data();
	std::vector<int> addr_delta(s->get_size() / s->get_entry_size(), 0);

	for (addr_update up : remap) {
		for (int i = 0; i < s->get_size() / s->get_entry_size(); ++i) {
			if (symtab[i].st_shndx != txt)
				continue;

			uint64_t rel_addr = symtab[i].st_value;
			if (ELF_ST_TYPE(symtab[i].st_info) == STT_FUNC)
				rel_addr &= ~((uint64_t)1);

			if (rel_addr == up.old_addr) {
				addr_delta[i] = up.new_addr - up.old_addr;
			}
		}
	}

	for (int i = 0; i < s->get_size() / s->get_entry_size(); ++i)
		symtab[i].st_value += addr_delta[i];
}

static void update_relocation_table(section *s, const std::vector<addr_update>& remap) {
	if (!s)
		return;

	Elf32_Rel *reltab = (Elf32_Rel *)s->get_data();
	std::vector<int> addr_delta(s->get_size() / s->get_entry_size(), 0);

	for (addr_update up : remap) {
		for (int i = 0; i < s->get_size() / s->get_entry_size(); ++i) {
			if (reltab[i].r_offset == up.old_addr) {
				addr_delta[i] = up.new_addr - up.old_addr;
			}
		}
	}

	for (int i = 0; i < s->get_size() / s->get_entry_size(); ++i)
		reltab[i].r_offset += addr_delta[i];
}

static std::vector<addr_update> get_addr_changes(
	const std::list<vins>& inl,
	const std::vector<uint8_t>& bin
) {
	std::vector<addr_update> addr_update_map(inl.size());

	uint64_t addr = 0;
	auto vi = inl.begin();
	for (int i = 0; i < inl.size(); ++i) {
		unsigned size;
		if (!vi->is_data()) {
			vins tmp = disassemble(&bin[addr], 0, addr).front();
			size = tmp.in.size;
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
		if (vi->is_original) {
			addr_update_map[i].old_addr = vi->addr;
			addr_update_map[i].new_addr = addr;
		} else {
			addr_update_map[i].old_addr = 0;
			addr_update_map[i].new_addr = 0;
		}

		++vi;
		addr += size;
	}

	return addr_update_map;
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
		if (i->mnemonic == "nop" && i->label.empty())
			il.erase(i);
		i = next;
	}
}

void lifter::save(std::string file) {
	if(!text_sec) {
		if (!reader.save(file))
			throw std::runtime_error("Failed to write to " + file);
	}

	std::stringstream assembly;

	int align = 1;
	for (const vins &b : this->instructions) {
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

	std::vector<addr_update> addr_update_map = get_addr_changes(instructions, bin);

	for (int i = 0; i < reader.sections.size(); ++i) {
		if (reader.sections[i]->get_name() == ".text") {
			update_symbol_table(sym_sec, addr_update_map, i);
			break;
		}
	}

	update_relocation_table(rel_sec, addr_update_map);

	if (!reader.save(file)) {
		throw std::runtime_error("Failed to write to " + file);
	}
}


bool lifter::load(std::string file) {
	if (!reader.load(file))
		return false;

	sym_sec = rel_sec = text_sec = nullptr;
	for (int i = 0; i < reader.sections.size(); ++i) {
		section* psec = reader.sections[i];
		if (psec->get_type() == SHT_SYMTAB) {
			sym_sec = psec;
		}
		else if (reader.sections[i]->get_name() == ".rel.text") {
			rel_sec = psec;
		}
		else if (reader.sections[i]->get_name() == ".text") {
			text_sec = psec;
		}
	}

	if (!text_sec)
		return true;

	instructions = disassemble(reader);
	add_labels_from_symbol_table();
	add_target_labels();
	merge_small_data(instructions);
	remove_nops(instructions);

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

		if (name == "$t" || name == "$d")
			continue;

		for (vins& in : this->instructions) {
			if (in.addr == value ||
			    type == STT_FUNC && in.addr == value - 1
			) {
				in.label = name;
				break;
			}
		}
	}
}

static bool is_relocatable(uint64_t addr, const section *rel) {
	if (!rel)
		return false;

	Elf32_Rel *reltab = (Elf32_Rel *)rel->get_data();

	for (int i = 0; i < rel->get_size() / rel->get_entry_size(); ++i) {
		if (reltab[i].r_offset == addr) {
			return true;
		}
	}

	return false;
}

void lifter::add_target_labels() {
	int label_cnt = 0;

	for (vins& in : this->instructions) {
		uint64_t addr;

		if (in.is_data())
			continue; // data

		if (in.target_label.size() != 0)
			continue;

		if (!calculate_target_address(&in.in, &in.detail, &addr))
			continue;
		auto temp = std::find_if(instructions.begin(), instructions.end(),
			[addr](vins &t) { return addr == t.addr; });
		if (temp == this->instructions.end())
			continue;
	
		if (temp->label.empty()) {
			if (is_relocatable(in.addr, rel_sec)) {
				temp->label = ".F" + std::to_string(label_cnt);
				assert (&*temp == &in);
			}
			else {
				temp->label = ".L" + std::to_string(label_cnt);
			}
			label_cnt++;
		} else if (!temp->label.compare(0, 2, ".F")) {
			// promote fake label to real one
			temp->label[1] = 'L';
			temp->target_label[1] = 'L';
		}
		
		in.target_label = temp->label;
	}
}