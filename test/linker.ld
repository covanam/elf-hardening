/* Entry Point */
ENTRY(Reset_Handler)

/* Highest address of the user mode stack */
_test_mem = 0x20008000;
_estack = 0x20008000;

/* Specify the memory areas */
MEMORY
{
    FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 256K
    RAM (rw) : ORIGIN = 0x20000000, LENGTH =  32K
    TEST_RAM(rw) : ORIGIN = 0x20008000, LENGTH = 32K
}

SECTIONS
{
    .isr_vector :
    {
        KEEP(*(.isr_vector))
    } >FLASH

    .text :
    {
        *(.text)
    } >FLASH

    .rodata :
    {
        *(.rodata)
    } >FLASH

    _sidata = LOADADDR(.data);

    .data : 
    {
        _sdata = .;
        *(.data)
        _edata = .;
    } >RAM AT> FLASH

    .bss :
    {
        _sbss = .;
        *(.bss)
        _ebss = .;
    } >RAM
}
