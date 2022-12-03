#include <elfio/elfio.hpp>
#include <cstdint>
#include <capstone/capstone.h>
#include <list>

struct bunit {
	const uint8_t *data;
	cs_insn in;
	uint64_t addr;
	uint64_t new_addr;
	int size;
	bunit(const cs_insn &p) {
		in = p;
		this->addr = p.address;
		this->data = nullptr;
		this->size = p.size;
	}
	bunit(const uint8_t *data, uint64_t size, uint64_t addr) {
		this->data = data;
		this->size = size;
		this->addr = addr;
	}
};

std::list<bunit> disassemble(const ELFIO::elfio& reader);
