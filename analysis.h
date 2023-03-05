#ifndef LIVENESS_H
#define LIVENESS_H

#include "cfg.h"
#include <exception>
#include <string>

class stack_analysis_failure : private std::runtime_error {
public:
        explicit stack_analysis_failure(const std::string& s) :
                std::runtime_error(s) {}
        
        std::string reason() const { return this->what(); }
};

void liveness_analysis(control_flow_graph &cfg);

void stack_offset_analysis(basic_block &entry);

#endif // LIVENESS_H
