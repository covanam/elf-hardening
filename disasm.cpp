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

using namespace ELFIO;

static std::list<vins> disassemble(const uint8_t *data, int size, uint64_t addr) {
	std::list<vins> ret;
	csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_ARM, (cs_mode)(CS_MODE_THUMB|CS_MODE_MCLASS), &handle) != CS_ERR_OK) {
		/* #TODO */
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
		/* #TODO */
	}
  
	if (ks_asm(ks, s.c_str(), 0, &encode, &size, &count) != KS_ERR_OK) {
		// #TODO
	} else {
		ret.assign(encode, encode + size);
	}

	// NOTE: free encode after usage to avoid leaking memory
	ks_free(encode);

	// close Keystone instance when done
	ks_close(ks);

	return ret;
}

static bool calculate_target_address(cs_detail *detail, uint64_t *addr) {
	bool use_pc = false;
	bool use_imm = false;
	int imm;

	for (
		const cs_arm_op *op = detail->arm.operands;
		op < detail->arm.operands + detail->arm.op_count;
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

	for (int i = 0; i < detail->groups_count; ++i) {
		if (detail->groups[i] == ARM_GRP_BRANCH_RELATIVE) {
			*addr = imm;
			return true;
		}
	}

	if (use_pc && use_imm) {
		uint64_t pc = (*addr + 4) & ~(uint64_t)2;
		*addr = pc + imm;
		return true;
	} else {
		return false;;
	}
}

vins::vins(const cs_insn &in) {
	this->in = in;
	this->addr = in.address;
	detail = *in.detail;

	mnemonic = in.mnemonic;
	operands = in.op_str;

	uint64_t dum;
	if (calculate_target_address(&detail, &dum)) {
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

vins::vins(uint8_t data, uint64_t addr) {
	mnemonic = ".byte";
	std::stringstream ss;
	ss << "0x" << std::hex << +data;
	operands = ss.str();
	this->addr = addr;
	in.id = 0;
}

vins::vins(const std::string s, uint64_t addr) {
	this->addr = addr;
	this->mnemonic = s;
}

std::ostream& operator<<(std::ostream& os, const vins &b) {
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

static void update_symtab(section *symtab, uint64_t old, uint64_t nnew) {
	for (int i = 0; i < symtab->get_size() / sizeof(Elf32_Sym); ++i) {
		Elf32_Sym *sym = ((Elf32_Sym *)symtab->get_data()) + i;
		if (sym->st_value == old)
			sym->st_value == nnew;
	}
}

static void update_reltab(section *reltab, uint64_t old, uint64_t nnew) {
	for (int i = 0; i < reltab->get_size() / sizeof(Elf32_Rel); ++i) {
		Elf32_Rel *rel = ((Elf32_Rel *)reltab->get_data()) + i;
		if (rel->r_offset == old)
			rel->r_offset == nnew;
	}
}

void lifter::save(std::string file) {
	std::stringstream assembly;
	for (const vins &b : this->instructions) {
		assembly << b << ';';
	}
	std::vector<uint8_t> bin = assemble(assembly.str());
	text_sec->set_data((const char *)&bin[0], bin.size());

	uint64_t addr = 0;
	for (vins vi : this->instructions) {
		unsigned size;
		if (vi.in.id) {
			vins tmp = disassemble(&bin[addr], 0, addr).front();
			size = tmp.in.size;
		} else {
			size = 1;
		}

		update_reltab(this->rel_sec, vi.addr, addr);
		update_symtab(this->sym_sec, vi.addr, addr);

		addr += size;
	} 

	reader.save(file);
}


lifter::lifter(std::string file) {
	reader.load(file);
	instructions = disassemble(reader);

	for (int i = 0; i < reader.sections.size(); ++i) {
		section* psec = reader.sections[i];
		if (psec->get_type() == SHT_SYMTAB) {
			sym_sec = psec;
		}
		else if (psec->get_type() == SHT_REL) {
			rel_sec = psec;
		}
		else if (reader.sections[i]->get_name() == ".text") {
			text_sec = psec;
		}
	}

	construct_labels();
}

void lifter::construct_labels() {
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

	int local_label_counter = 0;

	for (vins& in : this->instructions) {
		uint64_t addr = in.addr;

		if (in.in.id == 0)
			continue; // data

		if (in.target_label.size() != 0)
			continue;

		if (!calculate_target_address(&in.detail, &addr))
			continue;
		auto temp = std::find_if(instructions.begin(), instructions.end(),
			[addr](vins &t) { return addr == t.addr; });
		if (temp == this->instructions.end())
			continue;
	
		if (temp->label.empty()) {
			temp->label = ".L" + std::to_string(local_label_counter);
			local_label_counter++;
		}
		
		in.target_label = temp->label;
	}
}