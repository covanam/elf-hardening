#include <elfio/elfio.hpp>
#include <cstdint>
#include <capstone/capstone.h>
#include <list>
#include <sstream>

class vins {
public:
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

	friend std::ostream& operator<<(std::ostream& os, const vins &vi);
};

class lifter {
public:
	lifter(std::string file);
	void save(std::string file);
	std::list<vins> instructions;

private:
	void construct_labels();

	ELFIO::elfio reader;
	ELFIO::section *sym_sec;
	ELFIO::section *rel_sec;
	ELFIO::section *text_sec;
};
