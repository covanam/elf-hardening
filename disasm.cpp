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

static std::vector<bunit> code_to_bunit(const uint8_t *p, int size, uint64_t addr) {
        std::vector<bunit> ret;
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

static std::list<bunit> merge_instruction_data(
        const std::list<std::vector<bunit>> &inst,
        const std::list<raw_binary> &data
) {
        std::list<bunit> ret;

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
                for (const bunit &i : *i_itor) {
                        ret.push_back(i);
                }
                i_itor++;
                continue;

                add_data:
		for (int i = 0; i < d_itor->size; ++i)
			ret.push_back(bunit(d_itor->data[i], d_itor->addr + i));
                d_itor++;
        }

        return ret;
}

std::list<bunit> disassemble(const ELFIO::elfio& reader) {
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

        std::list<std::vector<bunit>> insn_list(code.size());

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

bunit::bunit(const std::string s, uint64_t addr) {
	std::vector<uint8_t> bin = assemble(s);
	static std::vector<bunit> t = code_to_bunit(&bin[0], bin.size(), addr);
	*this = t[0];
}

void dump_text(ELFIO::elfio& writer, const std::list<bunit> &d) {
        ELFIO::section *text;
	for (int i = 0; i < writer.sections.size(); ++i) {
		if (writer.sections[i]->get_name() == ".text") {
			text = writer.sections[i];
		}
	}

        int total_size = 0;
        for (const bunit &b : d) {
                total_size += b.size();
        }
        std::vector<uint8_t> dump(total_size);
        int i = 0;
        for (const bunit &b : d) {
		if (b.in.id == 0) {
			dump[i] = b.data;
			i++;
		} else if (b.target_label.length() != 0) {
			std::stringstream assembly;
			assembly << b;
			std::vector<uint8_t> tmp = assemble(assembly.str());
			std::copy(tmp.begin(), tmp.end(), &dump[i]);
			i += tmp.size();
			if (tmp.size() != b.size())
				std::cout << "resized: " << b << ' ' << b.size() << ' ' << tmp.size() << '\n';
                } else {
			std::copy(b.in.bytes, b.in.bytes + b.size(), &dump[i]);
			i += b.size();
		}
        }
	text->set_data((const char *)&dump[0], dump.size());
}

void fix_address(std::list<bunit> &x) {
	uint64_t curr_addr = x.begin()->addr;
	for (bunit &b : x) {
		b.addr = curr_addr;
		curr_addr += b.size();
	}
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

		for (bunit& in : this->instructions) {
			if (in.addr == value ||
			    type == STT_FUNC && in.addr == value - 1
			) {
				in.label = name;
				break;
			}
		}
	}

	int local_label_counter = 0;

	for (bunit& in : this->instructions) {
		uint64_t addr;

		if (in.target_label.size() != 0)
			continue;

		if (!in.calculate_target_address(&addr))
			continue;
		auto temp = std::find_if(instructions.begin(), instructions.end(),
			[addr](bunit &t) { return addr == t.addr; });
	
		if (temp->label.empty()) {
			temp->label = ".L" + std::to_string(local_label_counter);
			local_label_counter++;
		}
		
		in.target_label = temp->label;
	}
}