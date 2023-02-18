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
	vins(const std::string s);

	bool is_original;
	bool is_data() const;

	friend std::ostream& operator<<(std::ostream& os, const vins &vi);
};

class lifter {
public:
	bool load(std::string file);
	void save(std::string file);
	std::list<vins> instructions;

private:
	void add_labels_from_symbol_table();
	void add_target_labels(); 

	ELFIO::elfio reader;
	ELFIO::section *sym_sec;
	ELFIO::section *rel_sec;
	ELFIO::section *text_sec;
};
