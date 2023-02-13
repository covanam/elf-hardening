# Compiler settings. Only edit CFLAGS to include other header files.
CC=arm-none-eabi-gcc
AS=arm-none-eabi-as
LD=arm-none-eabi-ld
OBJCOPY=arm-none-eabi-objcopy

# Compiler flags
CFLAGS  = -Wall -Wextra -Werror
CFLAGS += -mthumb -march=armv7-m
CFLAGS += -ffreestanding

# Linker options
LDFLAGS = -nostdlib -Tlinker.ld

sos.elf: startup.o main.o data.o func.o
	$(LD) $(LDFLAGS) $^ -o sos.elf

clean:
	rm -f *.o sos.elf
