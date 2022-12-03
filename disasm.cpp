#include <string>
#include <capstone/capstone.h>
#include <tuple>
#include <list>
#include <vector>
#include <elfio/elfio.hpp>
#include "disasm.h"

using namespace ELFIO;

static std::vector<cs_insn> code_to_cs_insn(const uint8_t *p, int size, uint64_t addr) {
        std::vector<cs_insn> ret;
        csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &handle) != CS_ERR_OK) {
                /* #TODO */
        }
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

                if (i == sa.get_symbols_num() - 1) {
                        curr->size = text->get_data() + text->get_size() - (char*)last->data; 
                }

                last = curr;
        }

        return std::tuple(code, data);
}

static std::list<bunit> merge_instruction_data(
        const std::list<std::vector<cs_insn>> &inst,
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
                if ((*i_itor)[0].address < d_itor->addr)
                        goto add_inst;
                goto add_data;

                add_inst:
                for (const cs_insn &i : *i_itor) {
                        ret.push_back(bunit(i));
                }
                i_itor++;
                continue;

                add_data:
                ret.push_back(bunit(d_itor->data, d_itor->size, d_itor->addr));
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

        std::list<std::vector<cs_insn>> insn_list(code.size());

        auto il = insn_list.begin();
        for (const raw_binary &b : code) {
                *il = code_to_cs_insn(b.data, b.size, b.addr);
                ++il;
        }

        return merge_instruction_data(insn_list, data);
}