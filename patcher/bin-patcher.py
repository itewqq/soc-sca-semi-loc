#!/usr/bin/env python3
import argparse
import sys
import struct

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
except ImportError:
    print("Error: capstone module not installed. Install with: pip install capstone")
    sys.exit(1)

try:
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, KsError
except ImportError:
    print("Error: keystone-engine module not installed. Install with: pip install keystone-engine")
    sys.exit(1)

def find_zero_region(data, size):
    region = data.rfind(b'\x00' * size)
    return region if region != -1 else None

def main():
    parser = argparse.ArgumentParser(
        description="Patch uboot image to detour a BLR instruction to a custom function."
    )
    parser.add_argument("uboot", help="Path to uboot image binary")
    parser.add_argument("base_addr", help="Base address of uboot image (hex, e.g. 0x22D0000)")
    parser.add_argument("target_addr", help="Address of the target instruction to patch (hex, e.g. 0x22D73C)")
    args = parser.parse_args()

    try:
        base_addr = int(args.base_addr, 16)
        target_addr = int(args.target_addr, 16)
    except ValueError:
        print("Error: Base address and target address must be in hex (e.g., 0x22D0000)")
        sys.exit(1)

    try:
        with open(args.uboot, "rb") as f:
            data = bytearray(f.read())
    except IOError as e:
        print(f"Error opening file: {e}")
        sys.exit(1)

    target_offset = target_addr - base_addr
    if target_offset < 0 or (target_offset + 4) > len(data):
        print("Error: Target address is out of the binary file's range.")
        sys.exit(1)

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    insns = list(md.disasm(data[target_offset:target_offset+4], target_addr))
    if not insns:
        print("Error: Unable to disassemble at the target address.")
        sys.exit(1)
    insn = insns[0]
    if insn.mnemonic.lower() != "blr":
        print(f"Error: Expected target instruction to be 'BLR ??', but got: {insn.mnemonic} {insn.op_str}")
        sys.exit(1)
    print(f"Verified target instruction: {insn.mnemonic} {insn.op_str}")
    target_register = insn.op_str

    # Generate the assembly for the custom detour function.
    # This function saves the context, triggers GPIO before/after the call,
    # calls the original target (via X5), and then returns to the original control flow.
    asm_code = f"""
        .text
        .global custom_detour
custom_detour:
        // Save frame pointer and LR
        stp x29, x30, [sp, #-16]!
        mov x29, sp

        // Save x1, x0
        stp x1, x0, [sp, #-16]!

        // Setup trigger pin as output direction
        mov x0, #0xFEC40000
        mov w1, #0x400FFFF
        str w1, [x0, #8]

        // Trigger up: set GPIO high
        mov x0, #0xFEC40000
        mov w1, #0x400FFFF
        str w1, [x0]

        // Restore x1 and x0
        ldp x1, x0, [sp], #16

        // Call the original function, the args should be as same as the original one
        blr {target_register}

        // Save x1, x0
        stp x1, x0, [sp, #-16]!
        
        // Trigger down: set GPIO low
        mov x0, #0xFEC40000
        mov w1, #0x4000000
        str w1, [x0]

        // Restore x1 and x0
        ldp x1, x0, [sp], #16

        // Restore frame pointer and LR
        ldp x29, x30, [sp], #16
        ret
    """

    # Assemble the custom detour using Keystone.
    try:
        ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        encoding, count = ks.asm(asm_code)
    except KsError as e:
        print(f"Keystone assembly error: {e}")
        sys.exit(1)
    custom_detour_bin = bytes(encoding)
    print(f"Custom detour assembled successfully, size: {len(custom_detour_bin)} bytes.")

    insertion_offset = find_zero_region(data, len(custom_detour_bin))
    if insertion_offset is None:
        insertion_offset = len(data)
        data.extend(b'\x00' * len(custom_detour_bin))
        print("No zero region found; appending custom detour at the end of the binary.")
    else:
        print(f"Found zero region for custom detour at file offset 0x{insertion_offset:X}")

    data[insertion_offset:insertion_offset + len(custom_detour_bin)] = custom_detour_bin

    custom_detour_addr = base_addr + insertion_offset
    print(f"custom_detour function memory address: 0x{custom_detour_addr:X}")

    # Compute branch offset from the patched instruction (target_addr) to custom_detour_addr.
    offset = custom_detour_addr - target_addr
    # BL instruction offset must be within ±128 MB.
    if not (-128 * 1024 * 1024 <= offset < 128 * 1024 * 1024):
        print(f"Error: Branch offset ({offset}) is out of range (must be within ±128 MB).")
        sys.exit(1)

    # AArch64 BL instruction encoding:
    #   BL <offset> is 0x94000000 | ((offset >> 2) & 0x03FFFFFF)
    imm26 = (offset >> 2) & 0x03FFFFFF
    bl_instr = 0x94000000 | imm26
    print(f"Patching target instruction at file offset 0x{target_offset:X} with BL to custom_detour.")

    data[target_offset:target_offset+4] = struct.pack("<I", bl_instr)

    patched_filename = args.uboot + ".patched"
    try:
        with open(patched_filename, "wb") as f:
            f.write(data)
        print(f"Patched binary successfully written to {patched_filename}")
    except IOError as e:
        print(f"Error writing patched file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
