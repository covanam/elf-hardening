#include <stdint.h>

extern uint32_t test_data[];
extern uint32_t _test_mem;

uint32_t get_data(int i);

uint32_t giang_ngu(uint32_t x) {
    uint32_t *test_addr = &_test_mem;

    for (int i = 1; i < 15; ++i) {
        test_addr[i] = get_data(i);
    }

    *test_addr = x;
    
    return 0x22334578;
}

uint32_t get_data(int i) {
    return test_data[i];
}