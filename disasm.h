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
	int spill_slot;

	explicit vreg(int num) : num(num), spill_slot(-1) {}
	explicit vreg() : num(-1), spill_slot(-1) {}

	static vreg spill(int spill_slot) {
		vreg r;
		r.num = -1;
		r.spill_slot = spill_slot;
		return r;
	}

	static vreg spill(int spill_slot, int num) {
		vreg r;
		r.num = num;
		r.spill_slot = spill_slot;
		return r;
	}

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

	int rel = -1;
	std::vector<int> sym;

	std::string cond;

	bool update_flags() const { return _update_flags; }
	bool use_flags() const { return !!cond.size() || _use_carry || _use_ge; }

	void remove_condition();

	vins() = default;
	vins(const cs_insn &in);
	vins(uint8_t data, uint64_t addr);
	static vins ins_cmp(vreg r, int imm);
	static vins ins_cmp(vreg r1, vreg r2);
	static vins ins_b(const char *condition, const char *label);
	static vins ins_add(vreg d, vreg r1, vreg r2);
	static vins ins_add(vreg d, vreg r, int imm);
	static vins ins_sub(vreg d, vreg r, int imm);
	static vins ins_mov(vreg r, int imm);
	static vins ins_mov(vreg d, vreg s);
	static vins ins_str(vreg data, vreg addr, int offset);
	static vins ins_ldr(vreg data, vreg addr, int offset);
	static vins ins_str(vreg data, const std::string& label);
	static vins ins_ldr(vreg data, const std::string& label);
	static vins ins_return();
	static vins ins_arm_it(const char* cond);
	static vins ins_udf();
	static vins ins_msr(vreg r);
	static vins ins_mrs(vreg r);
	template<class list> static vins push_second_stack(const list& regs);
	template<class list> static vins pop_second_stack(const list& regs);
	template<class list> static vins stmia(vreg addr, const list& regs);
	template<class list> static vins ldmdb(vreg addr, const list& regs);

	static vins data_word(int data);

	static vins function_entry();
	static vins function_exit();

	void transfer_label(vins& in);

	int size() const;
	int64_t imm() const { return _imm; }
	int64_t& imm() { return _imm; }

	bool is_data() const;
	bool is_jump() const { return _is_jump; };
	bool is_call() const { return _is_call; };
	bool is_local_call() const;
	bool can_fall_through() const { return _can_fall_through; };

	bool is_function_return() const;

	bool is_pseudo() const;

	std::vector<vreg> regs;
	std::vector<unsigned> use, gen;

	friend std::ostream& operator<<(std::ostream& os, const vins &vi);

	std::set<vreg> live_regs;
	int stack_offset;
private:
	bool _is_jump, _is_call, _can_fall_through;
	bool _update_flags = false;
	bool _use_carry = false;
	bool _use_ge = false;
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
	void add_second_stack_address(
		std::list<vins>::iterator pos,
		const std::string& label
	);
	void add_second_stack_addresses();
	ELFIO::elfio reader;
	ELFIO::section *sym_sec;
	ELFIO::section *rel_sec;
	ELFIO::section *text_sec;
	ELFIO::section *str_sec;
};

#endif //DISASM_H
