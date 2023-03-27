#include <stdint.h>

#define STACK_SIZE 1024

uint32_t __second_stack[1 + STACK_SIZE / 4];
