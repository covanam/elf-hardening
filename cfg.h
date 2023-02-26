#ifndef ANALYSIS_H
#define ANALYSIS_H

#include "disasm.h"
#include <array>
#include <iostream>
#include <vector>
#include <list>

class basic_block : public std::list<vins> {
public:
	std::vector<basic_block*> predecessors;
	std::array<basic_block*, 2> successors;
	basic_block() {
		successors[0] = nullptr;
		successors[1] = nullptr;
		visited = false;
	}

	bool is_returning() const { return !successors[0] && !successors[1]; }
	std::string name() const {
		if (this->front().label[0] != '.')
			return this->front().label;
		return std::string();
	}

	bool visited; // for analysis

	friend std::ostream& operator<<(std::ostream& os, const basic_block& bb);
};

class control_flow_graph : public std::list<basic_block> {
public:
	void reset() {
		for (auto& bb : *this) {
			bb.visited = false;
		}
	}
};

control_flow_graph get_cfg(std::list<vins>& l);
std::list<vins> cfg_dump(control_flow_graph& cfg);

#endif //ANALYSIS_H
