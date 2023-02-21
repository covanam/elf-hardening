#ifndef DISASM_H
#define DISASM_H

#include <elfio/elfio.hpp>
#include <cstdint>
#include <capstone/capstone.h>
#include <list>
#include <sstream>
#include <set>

class vreg {
public:
	int num;
	vreg(int num) : num(num) {}
	vreg() : num(-1) {}
	friend std::ostream& operator<<(std::ostream& os, vreg r);

	friend bool operator<(const vreg l, const vreg r) {
		return l.num < r.num; }
	friend bool operator>(const vreg l, const vreg r) {
		return l.num > r.num; }
	friend bool operator==(const vreg l, const vreg r) {
		return l.num == r.num; }
	friend bool operator!=(const vreg l, const vreg r) {
		return l.num != r.num; }
	friend bool operator<=(const vreg l, const vreg r) {
		return l.num <= r.num; }
	friend bool operator>=(const vreg l, const vreg r) {
		return l.num >= r.num; }
};

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
	bool is_jump() const;
	bool is_call() const;
	bool can_fall_through() const;

	static bool is_fake_label(const std::string &label) {
		return !label.compare(0, 2, ".F");
	}

	std::vector<vreg> regs;
	std::vector<unsigned> use, gen;

	friend std::ostream& operator<<(std::ostream& os, const vins &vi);

	std::set<vreg> live_regs;
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

#endif //DISASM_H
