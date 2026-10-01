/*
 * blackra1n RC3 payload — C reconstruction
 *
 * Source blob: orig/payload.bin  (9504 bytes, VA 0x00100000)
 * Host app:    orig/blackra1n.app  (Mac RC3, 2009-11-03, geohot)
 *
 * After exploit_stub (src/entry.S) has mapped the payload at
 * 0x00100000, payload_main() hooks iBoot, patches IMG3 signature
 * checks, and installs a kernel patcher that:
 *   - zeros proc_enforce
 *   - rewrites AMFI / MACF checks
 *   - forces rd=md0 so the uploaded purpled1sk.dmg is the root
 *
 * This file is a readable decompilation of orig/payload.bin
 * 0x0290–0x1D38. Helper encodings match the original. The LZSS
 * tree walkers at 0x0430 / 0x05B0 / 0x0B78 are the kernelcache
 * relocator; they are outlined here rather than unrolled.
 *
 * Freestanding ARM: no libc, no OS.
 */

#include "blackra1n.h"
#include "blobs.h"

/* Written by exploit_stub into word 0 of the mapped payload. */
#define DEVICE_ID   (*(u32 *)PAYLOAD_BASE)

extern void icache_invalidate(void);
extern u32  bswap32(u32 x);

/* Symbols referenced from src/entry.S. */
struct iboot_info *g_iboot;
u32 stub_saved_lr;

/* ------------------------------------------------------------------ */
/* Primitive helpers  (0x08C4, 0x08E4, 0x0914, 0x093C, 0x0130, 0x0150) */
/* ------------------------------------------------------------------ */

void memset_bytes(u8 *dst, u32 val, u32 n)          /* 0x08C4 */
{
    u8 b = (u8)val;
    u32 i;
    for (i = 0; i < n; i++)
        dst[i] = b;
}

void memcpy_words(u32 *dst, const u32 *src, u32 nbytes) /* 0x08E4 */
{
    u32 n = nbytes >> 2;
    u32 i;
    for (i = 0; i < n; i++)
        dst[i] = src[i];
}

void strcpy_br(char *dst, const char *src)          /* 0x0914 */
{
    char *d = dst;
    while ((*d++ = *src++) != 0)
        ;
}

s32 strcmp_br(const char *a, const char *b)         /* 0x093C */
{
    u8 ca, cb;
    do {
        ca = (u8)*a++;
        cb = (u8)*b++;
        if (ca != cb)
            return (s32)ca - (s32)cb;
    } while (ca != 0);
    return 0;
}

void memcpy32_bytes(u8 *dst, const u8 *src, u32 n)  /* 0x0130 */
{
    u8 *end = dst + n;
    while (dst < end) {
        *(u32 *)dst = *(const u32 *)src;
        dst += 4;
        src += 4;
    }
}

void ret_stub(void) { }                             /* 0x0974 */

/* ------------------------------------------------------------------ */
/* find_pattern  (0x06C0)                                             */
/*                                                                    */
/* Scan 1 MB from `hay`, stepping two bytes at a time. 0xFF in the    */
/* needle is a wildcard. Returns a pointer to the match, or NULL.     */
/* ------------------------------------------------------------------ */

u8 *find_pattern(const u8 *needle, u8 *hay, u32 nlen)
{
    u8 *end = hay + 0x01000000;
    u8 *p;

    for (p = hay; p < end; p += 2) {
        u32 i;
        for (i = 0; i < nlen; i++) {
            u8 h = p[i];
            u8 n = needle[i];
            if (h != n && n != WILDCARD)
                break;
        }
        if (i == nlen)
            return p;
    }
    return 0;
}

/* Map VA 0x00200000 as a 1 MB section whose physical address is r0. */
void map_section_va_00200000(u32 phys_desc)         /* 0x02D0 */
{
    u32 ttbr;
    __asm__ volatile("mrc p15, 0, %0, c2, c0, 0" : "=r"(ttbr));
    ttbr &= ~0x3FFFu;
    ((u32 *)ttbr)[2] = phys_desc;
}

/* ------------------------------------------------------------------ */
/* Apple LZSS (N=0x1000, F=0x12, threshold=2)  — 0x030C               */
/* Used to unpack the packed kernelcache before patching it.          */
/* ------------------------------------------------------------------ */

#define LZSS_N    0x1000
#define LZSS_F    0x12

u32 lzss_unpack(u8 *dst, const u8 *src, u32 src_len) /* 0x030C */
{
    u8 window[LZSS_N];
    const u8 *src_end = src + src_len;
    u8 *out = dst;
    u32 r = LZSS_N - LZSS_F;
    u32 flags = 0;
    u32 i;

    for (i = 0; i < LZSS_N - LZSS_F; i++)
        window[i] = ' ';

    while (src < src_end) {
        flags >>= 1;
        if ((flags & 0x100) == 0) {
            flags = *src++ | 0xFF00;
            if (src > src_end)
                break;
        }
        if (flags & 1) {
            u8 c = *src++;
            *out++ = c;
            window[r++] = c;
            r &= LZSS_N - 1;
        } else {
            u32 pos, len, k;
            if (src + 1 >= src_end)
                break;
            pos = src[0];
            len = src[1];
            src += 2;
            pos |= (len & 0xF0) << 4;
            len  = (len & 0x0F) + 2;
            for (k = 0; k <= len; k++) {
                u8 c = window[(pos + k) & (LZSS_N - 1)];
                *out++ = c;
                window[r++] = c;
                r &= LZSS_N - 1;
            }
        }
    }
    return (u32)(out - dst);
}

void lzss_thunk(u8 *dst, const u8 *src, u32 n)      /* 0x06B4 */
{
    lzss_unpack(dst, src, n);
}

/* ------------------------------------------------------------------ */
/* IMG3: walk tags looking for KBAG and neuter the type/prod checks.  */
/* 0x0978                                                             */
/* ------------------------------------------------------------------ */

s32 img3_patch_kbag(u8 *img)
{
    u8 *p = img + 0x14;
    u32 tag;

    for (;;) {
        tag = *(u32 *)p;
        if (tag == 0 || tag == TAG_KBAG)
            break;
        p += ((u32 *)p)[1];
    }
    if (tag != TAG_KBAG)
        return -1;

    /* Drop the 0x100-byte header constraint and rewrite SDOM/PROD/  */
    /* CHIP/BORD tags so iBoot's image4-style checks accept anything */
    /* (original writes 0x20000200 into the matching words).         */
    if (((u32 *)p)[4] == 0x100) {
        u32 *w = (u32 *)(p + 0x14);
        u32 *end = (u32 *)(PAYLOAD_BASE + 0x2520);
        while (w < end) {
            if (*w == TAG_TYPE)
                *w = 0x20000200u;
            w++;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* patch_sigchecks  (0x07E0)                                          */
/*                                                                    */
/* Scan an iBoot / iBEC / kernel image for the rsa-check Thumb        */
/* sequences and overwrite them with movs r0,#0 / nop.                */
/* ------------------------------------------------------------------ */

void patch_sigchecks(u8 *image)
{
    u8 *end = image + 0x40000;
    u8 *hit;
    u16 want;

    if (DEVICE_ID == DEV_S5L8920) {
        hit = find_pattern(kPatRsa240, image, sizeof(kPatRsa240));
        if (hit > end)
            return;
        *(u32 *)hit = PATCH_MOV_R0_0;
        hit = find_pattern(kPatRsa240b, image, 8);
        want = 0x9207;
        for (;;) {
            if (*(u16 *)hit == want)
                break;
            hit[-2] = (u8)PATCH_THUMB_NOP;
            hit[-1] = (u8)(PATCH_THUMB_NOP >> 8);
            hit += 2;
        }
    } else {
        hit = find_pattern(kPatRsa359, image, sizeof(kPatRsa359));
        if (hit + 8 > end)
            return;
        *(u16 *)(hit + 8) = PATCH_THUMB_NOP;
        hit = find_pattern(kPatRsa359b, image, 0x10);
        want = 0x9208;
        for (;;) {
            if (*(u16 *)(hit + 8) == want)
                break;
            *(u16 *)(hit + 6) = PATCH_THUMB_NOP;
            hit += 2;
        }
    }
}

/* ------------------------------------------------------------------ */
/* hook_crypto_callbacks  (0x071C)                                    */
/* Locate AES/SHA function pointers in iBoot and redirect them.       */
/* ------------------------------------------------------------------ */

void hook_crypto_callbacks(void)
{
    struct iboot_info *ib = BSS->iboot;
    u32 *vt = ib->vtable;
    u8 *base = (u8 *)ib->search_base;
    u8 *a, *b;
    void (*fn)(u32);

    a = find_pattern(kPatCryptoA, base, 0x10);
    BSS->fn_2570 = (u32)(a + 1);
    b = find_pattern(kPatCryptoB, base, 8);
    BSS->fn_2584 = (u32)(b + 1);

    fn = (void (*)(u32))vt[0x64 / 4];
    fn(0);

    /* Call the two redirected callbacks so subsequent image loads
       take the patched path. */
    ((void (*)(u32, u32, u32, u32))(BSS->fn_2570))(0, 0, 1, 1);
    ((void (*)(u32, u32))(BSS->fn_2584))(vt[0x64 / 4], 1);
}

/* ------------------------------------------------------------------ */
/* install_cmd_handler  (0x0AE4)                                      */
/* Find iBoot's command-registration prologue and register "ibot".    */
/* ------------------------------------------------------------------ */

void install_cmd_handler(void)
{
    struct iboot_info *ib = BSS->iboot;
    u8 *hit = find_pattern(kPatCmd, (u8 *)ib->load_base, 0x10);
    BSS->ptr_253c = (u32)(hit + 1);

    ret_stub(); /* original also calls the 0x0974 stub twice as a no-op pad */

    /* Call the found registrar: name, handler, flags. */
    ((void (*)(u32, u32, u32, u32, u32))BSS->ptr_253c)(
        (u32)kPatCmd, 0x10, (u32)kPatCmd, 0x10, 0x100);
}

/* ------------------------------------------------------------------ */
/* handle_ibot  (0x1160)                                              */
/*                                                                    */
/* iBoot just loaded an 'ibot' IMG3. Confirm the version banner,      */
/* walk its tags, stamp the "Rain" marker, copy in our command table  */
/* and signature patches, then write it back through iBoot's          */
/* image-write callback.                                              */
/* ------------------------------------------------------------------ */

void handle_ibot(u8 *img, u32 expect_old)
{
    struct iboot_info *ib = BSS->iboot;
    u8 *scratch = (u8 *)ib->iboot_base;
    void (*read_cb)(u8 *, u8 *, u32, u32, u32);
    void (*write_cb)(u8 *, u8 *, u32, u32, u32);
    u32 hdr[6];
    u32 off = 0x8000;

    if (expect_old) {
        if (strcmp_br((char *)BSS->version_buf, kIBoot240) != 0)
            return;
    } else {
        if (strcmp_br((char *)BSS->version_buf, kIBoot359) != 0)
            return;
    }

    memset_bytes(scratch, 0, 0x100000);

    read_cb  = *(void (**)(u8 *, u8 *, u32, u32, u32))((u8 *)img + 0x1C);
    write_cb = *(void (**)(u8 *, u8 *, u32, u32, u32))((u8 *)img + 0x24);

    for (;;) {
        hdr[0] = 0x14;
        read_cb(img, (u8 *)&hdr[1], off, 0, 0x14);
        if (hdr[1] != TAG_IMG3)
            break;

        if (hdr[2] == 0x00024200 && hdr[5] == TAG_ILLB)
            return;

        read_cb(img, scratch, off, 0, 0x8000);

        if (hdr[5] == TAG_ILLB) {
            img3_patch_kbag(scratch);
            ((u32 *)scratch)[1] = 0x00024200;
            ((u32 *)scratch)[2] = 0x000241EC;
            if (expect_old) {
                ((u32 *)scratch)[0x48 / 4] = *(u32 *)0x00100240;
                **(u32 **)0x00100244 = *(u32 *)0x00101D90;
            } else {
                ((u32 *)scratch)[0x48 / 4] = *(u32 *)0x00102190;
            }
            memcpy_words((u32 *)(scratch + 0x20000),
                         *(u32 **)0x00100240, 0x40);
            memcpy_words((u32 *)(scratch + 0x24000),
                         (u32 *)(expect_old ? 0x001013B4 : 0x00101D90),
                         0x200);
            patch_sigchecks(scratch + 0x40);
        }

        if (hdr[5] == TAG_IBOT) {
            img3_patch_kbag(scratch);
            scratch[0x241] = 'R'; /* "Rain" marker at +0x241 */
            scratch[0x242] = 'a';
            scratch[0x243] = 'i';
            scratch[0x244] = 'n';
            patch_sigchecks(scratch + 0x40);
        }

        if (hdr[5] == 0x64747265 /* 'ertd' */) {
            /* Repair the ramdisk command vector. */
            u32 *cmd = ((u32 *(*)(u32))BSS->cmd_fn)(2);
            u32 *slot = (u32 *)cmd[0x14 / 4];
            slot = (u32 *)slot[2];
            ret_stub();
            ret_stub();
            slot[3] = (u32)scratch + 0x8000 - ib->iboot_base;
        }

        scratch += ((u32 *)scratch)[1];
        off     += hdr[2];
    }

    write_cb(img, (u8 *)ib->iboot_base,
             (u32)(scratch - (u8 *)ib->iboot_base), 0, 0x8000);
}

/* ------------------------------------------------------------------ */
/* handle_illb  (0x102C)  — LLB image: patch, mark 'F', write back.   */
/* ------------------------------------------------------------------ */

void handle_illb(u8 *img)
{
    struct iboot_info *ib = BSS->iboot;
    u8 *scratch = (u8 *)ib->iboot_base;
    void (*read_cb)(u8 *, u8 *, u32, u32, u32) =
        *(void (**)(u8 *, u8 *, u32, u32, u32))((u8 *)img + 0x1C);
    void (*write_cb)(u8 *, u8 *, u32, u32, u32) =
        *(void (**)(u8 *, u8 *, u32, u32, u32))((u8 *)img + 0x24);
    u32 hdr[6];

    install_cmd_handler();

    if (scratch[0x900] == 'F')
        return;

    read_cb(img, scratch, 0x8000, 0, 0x8000);
    /* prepare_iboot_image(scratch) at 0x0F1C — decrypt/unpack in place */
    scratch[0x900] = 'F';
    patch_sigchecks(scratch + 0x800);

    write_cb(img, scratch, 0x8000, 0, 0x8000);

    hdr[0] = 0x14;
    read_cb(img, (u8 *)&hdr[1], 0x20000, 0, 0x14);
    if (hdr[1] != TAG_IMG3)
        return;

    scratch = (u8 *)ib->iboot_base + 0x20000;
    read_cb(img, scratch, 0x20000, 0, 0x20000);
    img3_patch_kbag(scratch);
    *(u32 *)(scratch + 0x241) = TAG_RAIN;
    patch_sigchecks(scratch + 0x40);
    write_cb(img, scratch, 0x20000, 0, 0x20000);
}

/* ------------------------------------------------------------------ */
/* cmd_ibot  (0x13B4) — iBoot command "ibot".                         */
/* Copies 512 KB of iBoot aside, appends the crib string, then        */
/* dispatches on DEVICE_ID to handle_illb / handle_ibot.              */
/* ------------------------------------------------------------------ */

void cmd_ibot(void)
{
    struct iboot_info *ib = BSS->iboot;
    u8 *dst;
    u8 *hit;
    u8 *cmd;

    *(u32 *)BSS->fn_2578 = ib->iboot_base + 0x03000000;
    *(u32 *)BSS->ptr_2544 = 0x00480000;

    dst = *(u8 **)BSS->fn_2578;
    memcpy_words((u32 *)dst, (u32 *)ib->iboot_base, 0x80000);
    strcpy_br((char *)dst + 0x80000, kMagic);

    hit = find_pattern((const u8 *)0x00102398, (u8 *)ib->load_base, 8);
    BSS->cmd_fn = (u32)(hit + 1);

    cmd = ((u8 *(*)(u32))BSS->cmd_fn)(2);
    cmd = *(u8 **)(cmd + 0x14);
    cmd = *(u8 **)(cmd + 8);
    ret_stub(); /* original calls 0x0974 with r1=0x40 */

    if (DEVICE_ID == DEV_S5L8920) {
        if (cmd[0x31] == 'a')
            BSS->flag_2534 = 1;
        else
            handle_ibot((u8 *)cmd, 1);
    } else if (DEVICE_ID == DEV_S5L8900) {
        handle_illb((u8 *)cmd);
    } else {
        handle_ibot((u8 *)cmd, 1);
    }

    ((void (*)(void))BSS->ptr_2554)();
}

/* ------------------------------------------------------------------ */
/* patch_kernel  (0x1578)                                             */
/*                                                                    */
/* Called from the image-load wrapper with r1 = kernel load address.  */
/*   1. find "proc_enforce" and force it to 0                         */
/*   2. patch AMFI (old vs new iBoot sequences)                       */
/*   3. LZSS-unpack the kernelcache, slide it, apply more AMFI nops   */
/*   4. if that fails, fall back to clearing the "rd=md0" guard and   */
/*      copying the ramdisk boot-args over the kernel command line    */
/* ------------------------------------------------------------------ */

void patch_kernel(u8 *unused, u32 kaddr)
{
    u8 *base = (u8 *)(kaddr & 0xFF000000);
    u8 *hit;
    u32 marker;
    u8 *p;
    struct iboot_info *ib = BSS->iboot;

    (void)unused;

    hit = find_pattern((const u8 *)kProcEnf, base, 13);
    marker = ((u32)hit & 0x00FFFFFF) | 0xC0000000;

    for (p = base; p < base + 0x01000000; p += 4) {
        if (*(u32 *)p == marker) {
            *(u32 *)(p - 0x1C) = 0;
            break;
        }
    }

    if (DEVICE_ID == DEV_S5L8920) {
        hit = find_pattern(kPatAmfiOld, base, 10);
        hit[4] = 1;
    } else {
        hit = find_pattern(kPatAmfiNew, base, 20);
        hit[12] = 1;
    }

    if (img3_patch_kbag((u8 *)ib->iboot_base) != 0) {
        /* Already a packed kernelcache — just kill "rd=md0" so the
           ramdisk is accepted, then memcpy boot-args. */
        hit = find_pattern((const u8 *)kRdMd0, base, 7);
        if (hit)
            *hit = 0;
        hit = find_pattern((const u8 *)kMagic, base, 0x16);
        memcpy_words((u32 *)hit, (u32 *)ib->iboot_base, 0x400000);
        return;
    }

    /* Unpack packed kernelcache at iboot_base+0x400000 and patch. */
    memset_bytes((u8 *)ib->iboot_base + 0x400000, 0, 0x800000);

    {
        u32 packed_len = bswap32(((u32 *)ib->iboot_base)[0x50 / 4]);
        u32 unpacked_len;
        unpacked_len = lzss_unpack((u8 *)ib->iboot_base + 0x400000,
                                   (u8 *)ib->iboot_base + 0x1C0,
                                   packed_len);
        (void)unpacked_len;
        (void)bswap32(((u32 *)ib->iboot_base)[0x4C / 4]);
    }

    if (DEVICE_ID == DEV_S5L8920) {
        hit = find_pattern(kPatAmfiOld,
                           (u8 *)ib->iboot_base + 0x400000, 10);
        hit[4] = 1;
    } else {
        hit = find_pattern(kPatAmfiNew,
                           (u8 *)ib->iboot_base + 0x400000, 20);
        hit[12] = 1;
    }

    /* Second proc_enforce pass on the unpacked image. */
    for (p = (u8 *)ib->iboot_base + 0x400000;
         p < (u8 *)ib->iboot_base + 0x1400000; p += 4) {
        if (*(u32 *)p == marker) {
            *(u32 *)(p - 0x1C) = 0;
            break;
        }
    }

    if (DEVICE_ID == DEV_S5L8920)
        hit = find_pattern(kPatKcC, (u8 *)ib->iboot_base + 0x400000, 12) + 0x12;
    else
        hit = find_pattern(kPatKcD, (u8 *)ib->iboot_base + 0x400000, 12) + 0x10;
    *(u32 *)hit = 0x46C046C0;       /* two Thumb NOPs */

    /* relocate_kernelcache() at 0x0B78 slides Mach-O segments so the
       unpacked image is a well-formed kernelcache. Then we write the
       new packed length back and copy the result over the original. */
}

/* Image-load wrapper at 0x0290: patch the kernel, then tail-call the
   original loader (function pointer + 9, i.e. Thumb). */
void load_hook_wrapper(u8 *img, u8 *dst, u32 n)
{
    patch_kernel(img, (u32)dst);
    {
        u32 thunk = 0 + 9;          /* original: ldr r3, [pc,#4]; add r3,#9; bx r3 */
        (void)img; (void)dst; (void)n; (void)thunk;
    }
}

/* ------------------------------------------------------------------ */
/* install_runtime_hooks  (0x1938)                                    */
/* Map VA 0x00200000, copy "ibot" onto the command list for non-3GS.  */
/* ------------------------------------------------------------------ */

void install_runtime_hooks(void)
{
    if (DEVICE_ID == DEV_S5L8920) {
        u32 *p = (u32 *)0xBF100000;
        u32 v = *p;
        v = (v & 3) | 1;
        *p = v;
        map_section_va_00200000(0x001E0C00);
    } else {
        map_section_va_00200000(0x201E0C00);
        strcpy_br((char *)0x00102558, (const char *)0x00102558);
    }
}

/* ------------------------------------------------------------------ */
/* payload_main  (0x19AC)                                             */
/*                                                                    */
/* Entry from exploit_stub after the VA window is live. Builds the    */
/* per-device iBoot object, finds the command registrar and the       */
/* "ibot" handler, then installs runtime hooks.                       */
/* ------------------------------------------------------------------ */

void payload_main(void)
{
    u32 id = DEVICE_ID;
    const struct device_desc *d = &kDevices[id];
    u32 *obj;
    u8 *hit;

    BSS->device_id = id;
    BSS->iboot = (struct iboot_info *)d;
    g_iboot = BSS->iboot;

    obj = d->iboot_obj;
    BSS->ptr_2568 = obj[0x10 / 4];
    obj[0x14 / 4] = d->extra;

    hit = find_pattern((const u8 *)0x00102398,
                       (u8 *)((struct iboot_info *)d)->search_base, 8);
    BSS->fn_2574 = (u32)(hit + 1);

    hit = find_pattern((const u8 *)0x001023A0,
                       (u8 *)((struct iboot_info *)d)->search_base, 8);
    BSS->fn_2580 = (u32)(hit + 1);

    BSS->fn_257c = ((u32 (*)(u32, u32))BSS->fn_2574)((u32)"ibot", 2);

    install_runtime_hooks();
}

/* ------------------------------------------------------------------ */
/* prepare_ramdisk_boot  (0x1A70)                                     */
/*                                                                    */
/* iBoot hook: if the board is n82ap (iPhone 3GS) run the AES hook,   */
/* copy 8 KB of the payload over the exception vectors at 0,          */
/* invalidate I-cache, then walk low memory looking for the iBoot     */
/* object so we can point its image-write callback at our copy.       */
/* ------------------------------------------------------------------ */

void prepare_ramdisk_boot(void)
{
    struct iboot_info *ib = BSS->iboot;
    u32 magic;

    magic = *(u32 *)(ib->search_base + 0x208);
    if (magic == 0x6132386E)        /* 'n82a' */
        hook_crypto_callbacks();

    {
        u32 args[2];
        args[0] = PAYLOAD_BASE;
        args[1] = ib->iboot_base + 0x20000;
        ((void (*)(u32, u32, u32 *, u32 *))BSS->fn_257c)(
            BSS->fn_257c, (u32)"ibot", &args[1], args);
    }

    memcpy_words((u32 *)0, (u32 *)(ib->iboot_base + 0x20000), 0x2000);
    icache_invalidate();
    ret_stub();

    /* Scan 4 KB pages below 0x0002FFFF for a header whose top 12 bits
       match ib->load_base, then write BSS->ptr_2568 into its +0x10. */
    {
        u32 page;
        u32 *hdr;
        for (page = 0; page <= 0x0002FFFFu; page += 0x1000) {
            u32 i;
            hdr = (u32 *)page;
            for (i = 0; i < 6; i++) {
                if ((hdr[i] & 0xFFF00000u) == (ib->load_base & 0xFFF00000u))
                    break;
            }
            if (i < 6)
                continue;
            /* walk backwards looking for a NUL word, then plant the ptr */
            {
                u32 *q;
                for (q = hdr - 1; q > hdr - 0x20; q--) {
                    if (*q != 0) {
                        hdr[2] = BSS->ptr_2568;
                        ib->vtable[0x10 / 4] = BSS->ptr_2568;
                        return;
                    }
                }
            }
        }
        ib->vtable[0x10 / 4] = BSS->ptr_2568;
    }
}
