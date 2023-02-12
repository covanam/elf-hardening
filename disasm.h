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

	vins(const cs_insn &in);
	vins(uint8_t data, uint64_t addr);
	vins(const std::string s, uint64_t addr);

	int size() const {
		if (in.id != 0)
			return in.size;
		return 1;
	}

	friend std::ostream& operator<<(std::ostream& os, const vins &vi);
};

std::list<vins> disassemble(const ELFIO::elfio& reader);

void dump_text(ELFIO::elfio& writer, const std::list<vins> &d);

struct lifter {
	lifter(const ELFIO::elfio& reader);

	void construct_labels();

	std::list<vins> instructions;

	const ELFIO::elfio& reader;
	ELFIO::section *sym_sec;
	ELFIO::section *rel_sec;
	ELFIO::section *text_sec;
};
