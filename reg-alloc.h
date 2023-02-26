#include <map>
#include <set>
#include "disasm.h"

std::map<vreg, int> register_allocate(
	control_flow_graph& cfg,
	basic_block& entry
);
