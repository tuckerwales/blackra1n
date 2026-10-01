#!/usr/bin/env python3
"""Generate annotated GAS assembly from the original blackra1n RC3 payload."""
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
blob = (ROOT / "orig" / "payload.bin").read_bytes()
BASE = 0x00100000

LABELS = {
    0x0000: "_start",
    0x0040: "exploit_stub",
    0x00B4: "stub_after_reloc",
    0x00F4: "iboot_hook_entry",
    0x0130: "memcpy32",
    0x0150: "bswap32",
    0x0158: "icache_invalidate",
    0x0194: "call_iboot_4FF1E59D",
    0x01E0: "tramp_thumb_to_load_hook",
    0x0200: "tramp_thumb_to_lzss",
    0x0208: "str_geohot",
    0x020F: "str_tagline",
    0x0250: "thumb_relocate_iboot",
    0x0290: "load_hook_wrapper",
    0x02D0: "map_section_va_00200000",
    0x02F0: "indirect_call",
    0x030C: "lzss_unpack",
    0x0430: "lzss_tree_step",
    0x05B0: "lzss_tree_link",
    0x06B4: "lzss_thunk",
    0x06C0: "find_pattern",
    0x071C: "hook_crypto_callbacks",
    0x07E0: "patch_sigchecks",
    0x08C4: "memset_bytes",
    0x08E4: "memcpy_words",
    0x0914: "strcpy",
    0x093C: "strcmp",
    0x0974: "ret_stub",
    0x0978: "img3_patch_kbag",
    0x0AE4: "install_cmd_handler",
    0x0B78: "relocate_kernelcache",
    0x0F1C: "prepare_iboot_image",
    0x102C: "handle_illb",
    0x1160: "handle_ibot",
    0x13B4: "cmd_ibot",
    0x14E4: "handle_3gs_image",
    0x1578: "patch_kernel",
    0x1938: "install_runtime_hooks",
    0x19AC: "payload_main",
    0x1A70: "prepare_ramdisk_boot",
    0x1D38: "str_iboot_240",
    0x1D44: "str_iboot_359",
    0x1D50: "str_rd_md0",
    0x1D58: "str_progress",
    0x1D64: "str_ramdisk_too_large",
    0x1D78: "str_magic_crib",
    0x23DC: "str_fsboot",
    0x23E4: "str_proc_enforce",
    0x23F4: "str_bootx",
    0x2420: "device_table",
}

DATA_RANGES = [
    (0x0020, 0x0040),
    (0x00AC, 0x00B4),
    (0x00DC, 0x00F4),
    (0x012C, 0x0130),
    (0x0148, 0x0150),
    (0x0184, 0x0194),
    (0x01D0, 0x01E0),
    (0x0208, 0x0250),
    (0x1D38, 0x2520),
]

md_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
md_th = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

def in_data(off):
    return any(a <= off < b for a, b in DATA_RANGES)

lines = []
lines.append("/*")
lines.append(" * blackra1n RC3 payload — annotated reconstruction")
lines.append(" * Original: blackra1n.app/Contents/Resources/payload (9504 bytes)")
lines.append(" * SHA-256:  0220fe0bd995c6404de85bdc9cca32bedc82304c904988d40f577e249f2a924d")
lines.append(" * Linked at VA 0x00100000 after usb_control_msg(0x21, 2) overwrites")
lines.append(" * the ARM exception vectors at physical address 0.")
lines.append(" *")
lines.append(" * This file is a 1:1 word listing of the original blob so it")
lines.append(" * reassembles to the same bytes. Mnemonics are comments.")
lines.append(" */")
lines.append('.syntax unified')
lines.append('.arch armv6')
lines.append('.global _start')
lines.append(f".equ PAYLOAD_BASE, 0x{BASE:08X}")
lines.append("")
lines.append(".section .text")
lines.append(f".org 0")
lines.append("")

# ARM header 0x0-0x1e0 as instructions where possible
off = 0
while off < len(blob):
    if off in LABELS:
        lines.append("")
        lines.append(f"/* ----- {LABELS[off]} @ 0x{off:04X} ----- */")
        lines.append(f"{LABELS[off]}:")
    w = struct.unpack_from("<I", blob, off)[0] if off + 4 <= len(blob) else None

    # Thumb trampolines
    if off == 0x1E0 or off == 0x200:
        th = list(md_th.disasm(blob[off:off+4], BASE + off))
        for insn in th:
            raw = blob[insn.address - BASE: insn.address - BASE + insn.size]
            val = int.from_bytes(raw, "little")
            if insn.size == 2:
                lines.append(f"    .hword 0x{val:04X}    /* {insn.address-BASE:04X}: {insn.mnemonic} {insn.op_str} */")
            else:
                lines.append(f"    .word  0x{val:08X}    /* {insn.address-BASE:04X}: {insn.mnemonic} {insn.op_str} */")
        off += 4
        continue

    if off == 0x250:
        # thumb function until 0x288
        for insn in md_th.disasm(blob[0x250:0x288], BASE + 0x250):
            raw = blob[insn.address - BASE: insn.address - BASE + insn.size]
            val = int.from_bytes(raw, "little")
            if insn.size == 2:
                lines.append(f"    .hword 0x{val:04X}    /* {insn.address-BASE:04X}: {insn.mnemonic} {insn.op_str} */")
            else:
                lines.append(f"    .word  0x{val:08X}    /* {insn.address-BASE:04X}: {insn.mnemonic} {insn.op_str} */")
        off = 0x288
        continue

    if in_data(off) or off >= 0x1D38:
        # emit remaining as words, with string comments
        chunk = blob[off:off+4]
        if len(chunk) < 4:
            for b in chunk:
                lines.append(f"    .byte  0x{b:02X}")
            break
        w = struct.unpack("<I", chunk)[0]
        ascii_s = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        extra = ""
        if off in LABELS:
            extra = f" {LABELS[off]}"
        lines.append(f"    .word  0x{w:08X}    /* {off:04X}:{extra} {ascii_s} */")
        off += 4
        continue

    insns = list(md_arm.disasm(blob[off:off+4], BASE + off))
    if insns and insns[0].size == 4:
        insn = insns[0]
        lines.append(f"    .word  0x{w:08X}    /* {off:04X}: {insn.mnemonic:8s} {insn.op_str} */")
        off += 4
    else:
        lines.append(f"    .word  0x{w:08X}    /* {off:04X}: .word */")
        off += 4

lines.append("")
lines.append(f"/* payload end @ 0x{len(blob):04X}; runtime BSS continues to 0x4000 */")
lines.append(".section .bss")
lines.append(".align 4")
lines.append("g_bss:")
lines.append("    .space 0x4000 - 0x2520")
lines.append("")

(ROOT / "asm" / "payload.S").write_text("\n".join(lines) + "\n")
print("wrote", ROOT / "asm" / "payload.S", "lines", len(lines))
