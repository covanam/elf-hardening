#include <stdint.h>

#define STACK_SIZE 10000

uint32_t __second_stack_mem[STACK_SIZE / 4];
uint32_t* __second_stack = &__second_stack_mem[0];
