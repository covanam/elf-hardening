#ifndef CFG_H
#define CFG_H

#include "disasm.h"
#include <array>
#include <iostream>
#include <vector>
#include <list>
#include <set>
#include <initializer_list>

class basic_block : public std::list<vins> {
public:
	std::vector<basic_block*> predecessors;
	std::vector<basic_block*> successors;
	std::set<basic_block*> callers;
	basic_block* next;

	basic_block() {
		next = nullptr;
		visited = false;
		forward_visited = false;
		backward_visited = false;
	}

	basic_block(std::initializer_list<vins> ins)
		:std::list<vins>(ins)
	{
		next = nullptr;
		visited = false;
		forward_visited = false;
		backward_visited = false;
	}

	bool is_exit() const { return successors.empty(); }
	bool is_entry() const { return front().is_pseudo() && front().operands == "func_entry"; }

	bool visited; // for analysis
	bool forward_visited;
	bool backward_visited;

	friend std::ostream& operator<<(std::ostream& os, const basic_block& bb);
};

class control_flow_graph : public std::list<basic_block> {
public:
	void reset() {
		for (auto& bb : *this) {
			bb.visited = false;
			bb.forward_visited = false;
			bb.backward_visited = false;
		}
	}

	const std::set<std::string>& entries() const;
private:
	std::set<std::string> _entries;
};

control_flow_graph get_cfg(lifter& lift);
std::list<vins> cfg_dump(control_flow_graph& cfg);

#endif //CFG_H
