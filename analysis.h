#ifndef LIVENESS_H
#define LIVENESS_H

#include "cfg.h"

void liveness_analysis(control_flow_graph &cfg);

void stack_offset_analysis(control_flow_graph &cfg);

#endif // LIVENESS_H
