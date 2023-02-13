#!/usr/bin/env bash
#https://mcla.ug/blog/emulating-stm32-qemu.html
set -euo pipefail
TARGET=$1

make ${TARGET}

qemu-system-arm -cpu cortex-m3 -machine lm3s6965evb -nographic -no-reboot \
-gdb tcp::1234,ipv4 -kernel sos.elf > /dev/null &
QEMU_PID=$!

if [ ! -d "/proc/${QEMU_PID}" ]
then
    echo -ne "\033[31m Failed to start QEMU"
    echo -e "\033[0m"
    exit 1
fi

function read_address() {
    local ADDRESS=$1
    VALUE=$(gdb-multiarch \
        -q "${TARGET}" \
        -ex "target remote localhost:1234" \
        -ex "x/1xw ${ADDRESS}" \
        --batch | tail -2 | head -n1 | awk '{print $2}' )
}

function test_address() {
    local ADDRESS=$1
    local EX_VALUE=$2
    read_address "${ADDRESS}"
    if [ "$VALUE" = "${EX_VALUE}" ]
    then
        echo -ne "\033[32m [${ADDRESS}] good"
    else
        echo -ne "\033[31m [${ADDRESS}] $VALUE != ${EX_VALUE}"
    fi

    echo -e "\033[0m"
}

test_address "0x20008000" "0xa81a3200"
test_address "0x20008004" "0xa9f1234c"
test_address "0x20008008" "0xa81ab200"
test_address "0x2000800c" "0xa900234c"
test_address "0x20008010" "0xaabcd200"
test_address "0x20008014" "0xa9afdc4c"
test_address "0x20008018" "0xacb00000"
test_address "0x2000801c" "0x12345678"
test_address "0x20008020" "0xaaaaaaaa"
test_address "0x20008024" "0xbbbbbbbc"
test_address "0x20008028" "0xccccccdd"
test_address "0x2000802c" "0xdddddd11"
test_address "0x20008030" "0xeeeee111"
test_address "0x20008034" "0xffff111f"
test_address "0x20008038" "0x11122334"
test_address "0x2000803c" "0x22334578"
 
kill ${QEMU_PID} &> /dev/null
