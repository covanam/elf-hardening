#include <stdint.h>

extern uint8_t _estack; // end of ram
extern uint8_t _sidata; // init address of the .data section
extern uint8_t _sdata; // start address of the .data section
extern uint8_t _edata; // end address of the .data section
extern uint8_t _sbss; // start address of the .bss section
extern uint8_t _ebss; // end address of the .bss section

int main(void); // may not match the function's real signature, but does not matter

static void init_data_section(void)
{
	uint8_t *pSource = &_sidata;
	uint8_t *pDest = &_sdata;

	while (pDest != &_edata) {
		*pDest = *pSource;
		pDest++;
		pSource++;
	}
}

static void init_bss_section(void)
{
	uint8_t *p = &_sbss;

	while (p != &_ebss) {
		*p = 0;
		p++;
	}
}

void Reset_Handler(void)
{
	extern uint32_t _test_mem;
	_test_mem = 0xffffffff;
	init_data_section();

	init_bss_section();

	main();

	while (1) {
		__asm("wfi");
	}
}

void Default_Handler(void)
{
	while (1) {
		/* freeze */
	}
}

__attribute__((weak)) void NMI_Handler(void)
{
	Default_Handler();
}
__attribute__((weak)) void HardFault_Handler(void)
{
	Default_Handler();
}
__attribute__((weak)) void MemManage_Handler(void)
{
	Default_Handler();
}
__attribute__((weak)) void BusFault_Handler(void)
{
	Default_Handler();
}
__attribute__((weak)) void UsageFault_Handler(void)
{
	Default_Handler();
}
__attribute__((weak)) void SVC_Handler(void)
{
	Default_Handler();
}
__attribute__((weak)) void DebugMon_Handler(void)
{
	Default_Handler();
}
__attribute__((weak)) void PendSV_Handler(void)
{
	Default_Handler();
}
__attribute__((weak)) void SysTick_Handler(void)
{
	Default_Handler();
}

__attribute__((section(".isr_vector"))) void *isr_vector[] = {
	&_estack,	    Reset_Handler,     NMI_Handler,
	HardFault_Handler,  MemManage_Handler, BusFault_Handler,
	UsageFault_Handler, (void *)0,	       (void *)0,
	(void *)0,	    (void *)0,	       SVC_Handler,
	DebugMon_Handler,   (void *)0,	       PendSV_Handler,
	SysTick_Handler
};
