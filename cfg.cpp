#include "cfg.h"
#include <cassert>

std::ostream& operator<<(std::ostream& os, const basic_block& bb) {
	os << "Basic block (" << std::hex << bb.front().addr << ")\n";

	os << "From:\n";
	for (const auto i : bb.predecessors)
		os << '\t' << i->front().addr << '\n';

	os << "To:\n";
	for (const auto i : bb.successors)
		if (i)
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
	return !v.label.empty() && !vins::is_fake_label(v.label);
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
	if (!pred.successors[0])
		pred.successors[0] = &succ;
	else if (!pred.successors[1])
		pred.successors[1] = &succ;
	else assert(0);
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

std::list<basic_block> get_cfg(std::list<vins>& l) {
	std::list<basic_block> cfg;

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
			cur = &cfg.back();
		}

		i = next;
	}

	for (auto i = cfg.begin(); i != cfg.end(); ++i) {
		std::string &s = i->back().target_label;

		if (!s.empty() && !vins::is_fake_label(s) &&
		    i->back().is_jump() && !i->back().is_call())
			link_basic_blocks(*i, find_bb_with_label(cfg, s));

		if (i->back().can_fall_through()) {
			link_next_basic_block(i, cfg);
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
