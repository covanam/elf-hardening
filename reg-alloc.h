#include <map>
#include <set>
#include "disasm.h"

void virtualize_registers(control_flow_graph& cfg);
void allocate_registers(control_flow_graph& cfg);
