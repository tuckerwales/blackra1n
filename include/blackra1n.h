/*
 * blackra1n RC3 payload — types, constants, and BSS layout
 *
 * Recovered from blackra1n.app (Mac OS X, 2009-11-03) Resources/payload.
 * The blob is 9504 bytes, linked at VA 0x00100000. The host first uploads
 * it to the iBoot load address (0x41000000 on S5L8920, 0x09000000 on
 * S5L8900), then fires usb_control_msg(0x21, 2) so iBoot memcpy's 0x2000
 * bytes over the ARM exception vectors at address 0. Every vector
 * branches to exploit_stub, which maps VA 0x00100000 onto that load
 * address and continues in the relocated copy.
 *
 * Device id is taken from LR[31:24] of the interrupted iBoot:
 *   0x4F -> S5L8920 (iPhone 3GS)     id = 0
 *   other -> S5L8900 / S5L8720       id = 1
 *   0x0F -> S5L8922 (iPod touch 3G)  id = 2
 */

#ifndef BLACKRA1N_H
#define BLACKRA1N_H

/*
 * Function map in orig/payload.bin (VA = 0x00100000 + off):
 *
 *  0000  _start                 ARM exception vectors (all -> stub)
 *  0040  exploit_stub           device-id, map VA 0x00100000, copy, jump
 *  00B4  stub_after_reloc       call main, restore vectors, return to iBoot
 *  00F4  iboot_hook_entry       vtable hook: save regs, call ramdisk prep
 *  0130  memcpy32               word copy
 *  0150  bswap32
 *  0158  icache_invalidate
 *  0194  call_iboot_4FF1E59D    S5L8920 iBoot Thumb helper
 *  01E0  tramp (Thumb)          -> load_hook_wrapper
 *  0200  tramp (Thumb)          -> lzss_thunk
 *  0208  "geohot" / tagline
 *  0250  thumb_relocate_iboot   S5L8900 iBoot self-move
 *  0290  load_hook_wrapper      patch_kernel then tail-call loader
 *  02D0  map_section_va_00200000
 *  030C  lzss_unpack            Apple LZSS (N=4096, F=18)
 *  0430  lzss_tree_step
 *  05B0  lzss_tree_link
 *  06B4  lzss_thunk
 *  06C0  find_pattern           1 MB scan, 0xFF wildcard, stride 2
 *  071C  hook_crypto_callbacks
 *  07E0  patch_sigchecks        rsa-check -> movs r0,#0 / nop
 *  08C4  memset_bytes
 *  08E4  memcpy_words
 *  0914  strcpy
 *  093C  strcmp
 *  0978  img3_patch_kbag
 *  0AE4  install_cmd_handler    register "ibot"
 *  0B78  relocate_kernelcache
 *  102C  handle_illb
 *  1160  handle_ibot
 *  13B4  cmd_ibot
 *  1578  patch_kernel           proc_enforce, AMFI, rd=md0
 *  1938  install_runtime_hooks
 *  19AC  payload_main
 *  1A70  prepare_ramdisk_boot
 *  1D38  string pool
 *  2420  device_table[3]
 *  2520  BSS
 */

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef signed int     s32;

#define PAYLOAD_BASE        0x00100000u
#define PAYLOAD_COPY_SIZE   0x4000u

#define DEV_S5L8920         0   /* iPhone 3GS, iBoot around 0x4FF00000 */
#define DEV_S5L8900         1   /* iPhone 2G/3G, iPod 1G/2G */
#define DEV_S5L8922         2   /* iPod touch 3G */

#define TAG_IMG3            0x496d6733u  /* 'Img3' */
#define TAG_ILLB            0x696c6c62u  /* 'illb' */
#define TAG_IBOT            0x69626f74u  /* 'ibot' */
#define TAG_KBAG            0x4b424147u  /* 'GABK' as stored */
#define TAG_TYPE            0x53484954u  /* 'THIS' as stored */
#define TAG_RAIN            0x6e696152u  /* 'Rain' */

/* iBoot RSA-check patch: two Thumb "movs r0, #0" */
#define PATCH_MOV_R0_0      0x20002000u
#define PATCH_THUMB_NOP     0x2200u

#define WILDCARD            0xFFu

/* Per-device descriptor, 0x14 bytes, table at 0x2420. */
struct device_desc {
    u32 iboot_base;     /* +0x00  0x4FF00000 / 0x18000000 / 0x0FF00000 */
    u32 map_phys;       /* +0x04 */
    u32 load_addr;      /* +0x08  0x41000000 / 0x09000000 */
    u32 *iboot_obj;     /* +0x0C  pointer into live iBoot */
    u32 extra;          /* +0x10 */
};

/* Runtime iBoot object the payload hangs off g_iboot. */
struct iboot_info {
    u32 load_base;      /* +0x00 */
    u32 search_base;    /* +0x04  pattern-scan window */
    u32 iboot_base;     /* +0x08  iBoot text */
    u32 pad_0c;
    u32 pad_10;
    u32 *vtable;        /* +0x14  iBoot callback table */
};

/*
 * BSS begins at 0x00102520 (end of the 9504-byte image) and the stub
 * copies 0x4000 bytes, so this block is available at runtime.
 * Offsets recovered from PC-relative loads in the blob.
 */
struct payload_bss {
    u32 unused_2520[5];         /* 0x2520 */
    u32 flag_2534;              /* 0x2534 */
    u32 device_id;              /* 0x2538  copy of DEVICE_ID */
    u32 ptr_253c;               /* 0x253c */
    u32 unused_2540;
    u32 ptr_2544;               /* 0x2544 */
    u32 cmd_fn;                 /* 0x2548 */
    u32 (*indirect)(void);      /* 0x254c */
    u32 ptr_2550;               /* 0x2550 */
    u32 ptr_2554;               /* 0x2554 */
    u32 version_buf;            /* 0x2558 */
    u32 unused_255c[3];
    u32 ptr_2568;               /* 0x2568 */
    struct iboot_info *iboot;   /* 0x256c */
    u32 fn_2570;                /* 0x2570 */
    u32 fn_2574;                /* 0x2574 */
    u32 fn_2578;                /* 0x2578 */
    u32 fn_257c;                /* 0x257c  found "ibot" command handler */
    u32 fn_2580;                /* 0x2580 */
    u32 fn_2584;                /* 0x2584 */
};

#define BSS ((struct payload_bss *)(PAYLOAD_BASE + 0x2520))

#endif
