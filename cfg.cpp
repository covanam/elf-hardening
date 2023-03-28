#include "cfg.h"
#include <cassert>

std::ostream& operator<<(std::ostream& os, const basic_block& bb) {
	os << "Basic block (" << std::hex << bb.front().addr << ")\n";

	os << "From:\n";
	for (const auto i : bb.predecessors)
		os << '\t' << i->front().addr << '\n';

	os << "To:\n";
	for (const auto i : bb.successors)
		os << '\t' << i->front().addr << '\n';
	os << std::dec;

	os << "Content:\n";
	for (auto i : bb) {
		os << '\t' << i << " (";
		for (auto r : i.live_regs)
			os << r << ' ';
		os << ")\n";
	}
	os << '\n';

	return os;
}

static bool is_basic_block_end(const vins& v, const vins& next) {
	if (v.is_data()) {
		return !next.is_data();
	}
	return v.is_jump();
}

static bool is_basic_block_start(const vins& v) {
	if (v.is_data())
		return false;
	return !v.label.empty();
}

static basic_block& find_bb_with_label(
	std::list<basic_block>& cfg,
	const std::string& label)
{
	for (auto& bb : cfg) {
		const std::string &s = bb.front().label;
		if (s == label) {
			return bb;
		}
	}
	assert(0);
}

static void link_basic_blocks(basic_block& pred, basic_block& succ) {
	pred.successors.push_back(&succ);
	succ.predecessors.push_back(&pred);
}

static void link_next_basic_block(
	std::list<basic_block>::iterator pred,
	std::list<basic_block>& cfg)
{
	std::list<basic_block>::iterator succ = std::next(pred);
	if (succ == cfg.end())
		return;
	
	link_basic_blocks(*pred, *succ);
}

static void link_follow_function_call(
	basic_block* const caller,
	basic_block* const callee
) {
	if (callee->callers.find(caller) != callee->callers.end())
		return;
	
	callee->callers.insert(caller);

	if (callee->back().is_function_return()) {
		if (caller) {
			basic_block* return_bb = caller->next;
			for (auto succ : callee->successors)
				if (succ == return_bb)
					return;
			link_basic_blocks(*callee, *return_bb);
		}
	}
	else if (callee->back().is_call()) {
		if (callee->back().is_local_call())
			link_follow_function_call(callee, callee->successors[0]);
		link_follow_function_call(caller, callee->next);
	}
	else {
		for (auto succ : callee->successors) {
			link_follow_function_call(caller, succ);
		}
	}
}

control_flow_graph get_cfg(lifter& lift) {
	control_flow_graph cfg;

	std::list<vins>& l = lift.instructions;
	std::set<std::string>& functions = lift.functions;

	if (l.empty())
		return cfg;

	cfg.push_back(basic_block());
	basic_block *cur = &cfg.back();

	for (auto i = l.begin(); i != l.end();) {
		auto next = std::next(i);

		cur->splice(cur->end(), l, i);

		if (next == l.end())
			break;

		if (is_basic_block_end(*i, *next) || is_basic_block_start(*next)) {
			cfg.push_back(basic_block());
			cur->next = &cfg.back();
			cur = &cfg.back();
		}

		i = next;
	}

	for (auto i = cfg.begin(); i != cfg.end(); ++i) {
		std::string &s = i->back().target_label;

		if (!s.empty() && i->back().is_jump())
			link_basic_blocks(*i, find_bb_with_label(cfg, s));

		if (i->back().can_fall_through() ||
		    i->back().is_call() && !i->back().is_local_call()) {
			link_next_basic_block(i, cfg);
		}
	}

	for (auto& bb : cfg) {
		if (functions.find(bb.front().label) != functions.end()) {
			link_follow_function_call(nullptr, &bb);
		}
	}

	/* calling convention */
	for (auto& bb : cfg) {
		if (functions.find(bb.front().label) != functions.end()) {
			vins tmp = vins::function_entry();
			bb.front().transfer_label(tmp);
			bb.push_front(std::move(tmp));
		}
		if (bb.back().is_function_return() &&
		    bb.callers.find(nullptr) != bb.callers.end()) {
			vins tmp = vins::function_exit();
			bb.push_back(std::move(tmp));
		}
	}

	return cfg;
}

std::list<vins> cfg_dump(control_flow_graph& cfg) {
	std::list<vins> dump;

	for (control_flow_graph::iterator i = cfg.begin(); i != cfg.end();) {
		auto next = std::next(i);
		dump.splice(dump.end(), *i);
		cfg.erase(i);
		i = next;
	}
	
	return dump;
}
