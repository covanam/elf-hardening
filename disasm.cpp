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

static std::vector<vins> code_to_bunit(const uint8_t *p, int size, uint64_t addr) {
	std::vector<vins> ret;
	csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_ARM, (cs_mode)(CS_MODE_THUMB|CS_MODE_MCLASS), &handle) != CS_ERR_OK) {
		/* #TODO */
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	count = cs_disasm(handle, p, size, addr, 0, &insn);

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

struct raw_binary {
	const uint8_t *data;
	int size;
	uint64_t addr;

	raw_binary(const uint8_t *data, int size, uint64_t addr) :
		data(data), size(size), addr(addr) {}
};

static std::tuple<std::list<raw_binary>, std::list<raw_binary>>
split_text_section(const ELFIO::section *text, const symbol_section_accessor &sa) {
	std::list<raw_binary> code, data;

	raw_binary *last = nullptr;
	raw_binary *curr = nullptr;

	for (unsigned int i = 1; i < sa.get_symbols_num(); ++i ) {
		std::string name;
		Elf64_Addr value;
		Elf_Xword size;
		unsigned char bind;
		unsigned char type;
		Elf_Half section_index;
		unsigned char other;

		last = curr;

		sa.get_symbol(i, name, value, size, bind,
		type, section_index, other);

		if (section_index != text->get_index())
			continue;

		const uint8_t *p = (const uint8_t*)text->get_data() + value;

		/* gcc use $t and $d symbols to mark instructions and data */
		if (name == "$d") {
			data.push_back(raw_binary(p, 0, value));
			curr = &data.back(); 
		} else if (name == "$t") {
			code.push_back(raw_binary(p, 0, value));
			curr = &code.back();
		} else {
			continue;
		}
		
		if (last != nullptr) {
			last->size = curr->addr - last->addr;
		}
	}

	curr->size = text->get_data() + text->get_size() - (char*)last->data; 

	return std::tuple(code, data);
}

static std::list<vins> merge_instruction_data(
	const std::list<std::vector<vins>> &inst,
	const std::list<raw_binary> &data
) {
	std::list<vins> ret;

	auto d_itor = data.begin();
	auto i_itor = inst.begin();

	while (d_itor != data.end() || i_itor != inst.end()) {
		if (i_itor == inst.end())
			goto add_data;
		if (d_itor == data.end())
			goto add_inst;
		if ((*i_itor)[0].addr < d_itor->addr)
			goto add_inst;
		goto add_data;

		add_inst:
		for (const vins &i : *i_itor) {
			ret.push_back(i);
		}
		i_itor++;
		continue;

		add_data:
		for (int i = 0; i < d_itor->size; ++i)
			ret.push_back(vins(d_itor->data[i], d_itor->addr + i));
		d_itor++;
	}

	return ret;
}

std::list<vins> disassemble(const ELFIO::elfio& reader) {
	ELFIO::section *text = nullptr, *symtab;
	for (int i = 0; i < reader.sections.size(); ++i) {
		if (reader.sections[i]->get_name() == ".text") {
			text = reader.sections[i];
		} else if (reader.sections[i]->get_type() == SHT_SYMTAB) {
			symtab = reader.sections[i];
		}
	}

	symbol_section_accessor symbols(reader, symtab);

	auto temp = split_text_section(text, symbols);
	std::list<raw_binary> code = std::get<0>(temp);
	std::list<raw_binary> data = std::get<1>(temp);

	std::list<std::vector<vins>> insn_list(code.size());

	auto il = insn_list.begin();
	for (const raw_binary &b : code) {
		*il = code_to_bunit(b.data, b.size, b.addr);
		++il;
	}

	return merge_instruction_data(insn_list, data);
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
	std::vector<uint8_t> bin = assemble(s);
	static std::vector<vins> t = code_to_bunit(&bin[0], bin.size(), addr);
	*this = t[0];
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

void dump_text(ELFIO::elfio& writer, const std::list<vins> &d) {
	ELFIO::section *text;
	for (int i = 0; i < writer.sections.size(); ++i) {
		if (writer.sections[i]->get_name() == ".text") {
				text = writer.sections[i];
		}
	}

	std::stringstream assembly;
	for (const vins &b : d) {
		assembly << b << ';';
	}
	std::vector<uint8_t> tmp = assemble(assembly.str());
	text->set_data((const char *)&tmp[0], tmp.size());
}


lifter::lifter(const ELFIO::elfio& reader) : reader(reader)
{
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
	
		if (temp->label.empty()) {
			temp->label = ".L" + std::to_string(local_label_counter);
			local_label_counter++;
		}
		
		in.target_label = temp->label;
	}
}