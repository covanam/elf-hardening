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
	}
	friend std::ostream& operator<<(std::ostream& os, const basic_block& bb);
};

std::list<basic_block> get_cfg(std::list<vins>& l);

#endif //ANALYSIS_H
