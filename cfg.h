#ifndef ANALYSIS_H
#define ANALYSIS_H

#include "disasm.h"
#include <array>
#include <iostream>
#include <vector>
#include <list>
#include <set>

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

	bool is_exit() const { return successors.empty(); }
	bool is_entry() const { return front().label.size() && front().label[0] != '.'; }

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

#endif //ANALYSIS_H
