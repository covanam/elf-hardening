#include <iostream>
#include <elfio/elfio.hpp>
using namespace ELFIO;

void patch_section(elfio *reader, section *sec, Elf32_Addr addr, const char *value, int size) {
	/* insert the patch to the section*/
	const char *data = (const char *)sec->get_data();
	char *newdata = new char[sec->get_size() + size];
	std::copy(data, data + addr, newdata);
	std::copy(value, value + size, newdata + addr);
	std::copy(data + addr, data + sec->get_size(), newdata + addr + size);
	sec->set_data(newdata, sec->get_size() + size);
	delete[] newdata;

	for ( int i = 0; i < reader->sections.size(); ++i ) {
		section* psec = reader->sections[i];

		if (psec->get_type() == SHT_SYMTAB) {
			/* fix all symbols affected by the patch */
			symbol_section_accessor symbols(*reader, psec);
			for ( unsigned int i = 1; i < symbols.get_symbols_num(); ++i ) {
				Elf32_Sym *s = (Elf32_Sym*)(psec->get_data() + sizeof(*s) * i);
				section *tsec = reader->sections[s->st_shndx];
				if (tsec != sec)
					continue;
				if (s->st_value < addr && s->st_value + s->st_size > addr)
					s->st_size += size;
				else if (s->st_value > addr)
					s->st_value += size;
			}
			
		}
		else if (psec->get_type() == SHT_REL) {
			/* fix all relocation entries affected by the patch */
			section *tsec = reader->sections[psec->get_info()];
			if (tsec != sec)
				continue;
			for (int j = 0; j < psec->get_size() / psec->get_entry_size(); ++j) {
				Elf32_Rel *r = (Elf32_Rel*)(psec->get_data() + j * sizeof(Elf32_Rel));
				if (r->r_offset < addr)
					continue;
				r->r_offset += size;
			}
		}
	}
}

int main(int argc, char *argv[]) {
	ELFIO::elfio reader;
	reader.load(argv[1]);
	const char *patch = "\x00\xbf\x00\xbf";
	for ( int i = 0; i < reader.sections.size(); ++i ) {
		section* psec = reader.sections[i];

		if ( psec->get_type() == SHT_SYMTAB ) {
			symbol_section_accessor symbols(reader, psec );
			for ( unsigned int j = 1; j < symbols.get_symbols_num(); ++j ) {
				std::string name;
				Elf64_Addr value;
				Elf_Xword size;
				unsigned char bind;
				unsigned char type;
				Elf_Half section_index;
				unsigned char other;
				symbols.get_symbol(j, name, value, size, bind,
					type, section_index, other);
				if (type == STT_FUNC) {
					patch_section(
						&reader,
						reader.sections[section_index],
						value - 1 + size,
						patch,
						4
						);
				}
			}
		}
	}
	reader.save(argv[2]);
}