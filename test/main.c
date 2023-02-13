#include <stdint.h>

extern uint32_t _test_mem;

uint32_t giang_ngu(uint32_t x);

int main()
{
	uint32_t x = giang_ngu(0xa81a3200);

	uint32_t *test_addr = &_test_mem;

	test_addr[15] = x;

	while (1)
		__asm__("wfi");
}
