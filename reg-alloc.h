#include <map>
#include <set>
#include "disasm.h"

std::map<vreg, int> register_allocate(
	control_flow_graph& cfg,
	basic_block& entry
);

void split_registers(control_flow_graph& cfg, const std::string& entry);

void spill(control_flow_graph& cfg);
