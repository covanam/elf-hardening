#include <map>
#include <set>
#include "disasm.h"

std::map<vreg, vreg> register_allocate(
	control_flow_graph& cfg,
	basic_block& entry
);

void split_registers(control_flow_graph& cfg);

void spill(control_flow_graph& cfg);
