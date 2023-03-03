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
	uint64_t addr;

	std::string target_label;
	std::string label;

	vins() = default;
	vins(const cs_insn &in);
	vins(uint8_t data, uint64_t addr);
	static vins ins_cmp(vreg r, int imm);
	static vins ins_b(const char *condition, const char *label);
	static vins ins_add(vreg d, vreg r1, vreg r2);
	static vins ins_mov(vreg r, int imm);

	int size() const;
	int64_t imm() const { return _imm; }

	bool is_data() const;
	bool is_jump() const { return _is_jump; };
	bool is_call() const { return _is_call; };
	bool can_fall_through() const { return _can_fall_through; };
	bool is_function_return() const;

	static bool is_fake_label(const std::string &label) {
		return !label.compare(0, 2, ".F");
	}

	std::vector<vreg> regs;
	std::vector<unsigned> use, gen;

	friend std::ostream& operator<<(std::ostream& os, const vins &vi);

	std::set<vreg> live_regs;
	int stack_offset;
private:
	bool _is_jump, _is_call, _can_fall_through;
	int64_t _imm = 0;
	int _size;
};

class lifter {
public:
	bool load(std::string file);
	void save(std::string file);
	std::list<vins> instructions;

	std::set<std::string> functions;

private:
	void add_labels_from_symbol_table();
	void add_target_labels(); 
	void get_function_name();

	ELFIO::elfio reader;
	ELFIO::section *sym_sec;
	ELFIO::section *rel_sec;
	ELFIO::section *text_sec;
};

#endif //DISASM_H
