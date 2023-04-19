import re
import subprocess
from subprocess import Popen, PIPE, check_output
import time
import os

def test(elffile):
    qemu_cmd = "qemu-system-arm -cpu cortex-m3 -machine lm3s6965evb \
            -nographic -no-reboot -gdb tcp::1234,ipv4 -kernel " + elffile

    qemu = Popen(qemu_cmd.split(),stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)

    sleep_countdown = 10
    while True:
        out = subprocess.getoutput(
            "gdb-multiarch -q %s \
            -ex \"target remote localhost:1234\" \
            -ex \"x/1xw 0x20008000\" \
            --batch" % elffile)
        value = re.findall(r"0x20008000:\s+(.+)", out)[0]

        if value == "0xffffffff" and sleep_countdown != 0:
            sleep_countdown -= 1
            print("Wait for binary to finish (%d)" % sleep_countdown, end='\r')
            time.sleep(1)
        else:
            break


    if value == "0xcafebabe":
        print(elffile, "\033[92mGood!\033[0m")
    else:
        print(elffile, "\033[93mBad:\033[0m", value)
    qemu.kill()

test("tinycrypt/tests/secboot_sha256.elf")
test("tinycrypt/tests/secboot_hmac.elf")
test("tinycrypt/tests/test_aes.elf")
test("tinycrypt/tests/test_cbc_mode.elf")
test("tinycrypt/tests/test_cmac_mode.elf")
test("tinycrypt/tests/test_ctr_mode.elf")
test("tinycrypt/tests/test_ctr_prng.elf")
#./test_elf.sh tinycrypt/tests/test_ecc_dh.elf
#./test_elf.sh tinycrypt/tests/test_ecc_dsa.elf
test("tinycrypt/tests/test_hmac_prng.elf")
test("tinycrypt/tests/test_hmac.elf")
test("tinycrypt/tests/test_sha256.elf")