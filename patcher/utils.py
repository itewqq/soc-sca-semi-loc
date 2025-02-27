import subprocess

from enum import Enum, auto
from typing import List, TypedDict
from string import Template
from pwn import ELF
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_ARM, KsError

class InstDisPiferException(Exception):
    pass

class NoFreeRegPiferException(Exception):
    pass

class MultiHooksSingleAddrPiferException(Exception):
    pass

def compile_helper(code):
    try:
        ks = Ks(KS_ARCH_ARM64, KS_MODE_ARM)
        encoding, count = ks.asm(code)
        print("%s = %s (number of statements: %u)" % (code, encoding, count))
    except KsError as e:
        print("ERROR: %s" % e)

def disasm_helper(code_bytes, target_pc, inst_len=0):
    # print(code_bytes, inst_len)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    if inst_len == 0:
        try:
            res = list(md.disasm(code_bytes[:4], target_pc))
            if len(res) == 0:
                raise InstDisPiferException(
                    f"Failed to disasmble the target instruction at {hex(target_pc)}: {code_bytes[:4]}!")
            inst_len = res[0].size
        except InstDisPiferException as e:
            print(e)
            exit(0)

    code_bytes = code_bytes[:inst_len]
    inst = list(md.disasm(code_bytes, target_pc))[0]
    return inst, inst_len