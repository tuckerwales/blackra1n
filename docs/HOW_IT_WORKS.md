# blackra1n RC3 payload — how it actually works

This is a byte-level description of George Hotz’s **blackra1n RC3** (Mac OS X
build, 3 November 2009): the host program, the USB transaction that hijacks
iBoot, and the 9504-byte ARM payload that then patches iBoot and the kernel.
Every constant below is taken from `orig/blackra1n.app` and
`orig/payload.bin` (SHA-256
`0220fe0bd995c6404de85bdc9cca32bedc82304c904988d40f577e249f2a924d`).

It is a reconstruction of a 2009 jailbreak for iPhone OS **3.1 / 3.1.1 /
3.1.2**. Those firmwares have been obsolete for a decade and a half. This
document is historical reverse engineering, not a how-to for attacking
anything still in use.

---

## 1. What you are looking at

`blackra1n.app` is a universal Mach-O (i386 + PowerPC) Cocoa program. It talks
to a device in **iBoot recovery mode** over USB, using a mix of Apple’s
`MobileDevice.framework` and a bundled copy of libusb. The interesting files
are not in the executable; they are resources:

| Resource | Size | Role |
|---|---|---|
| `Contents/Resources/payload` | 9504 (`0x2520`) | ARM payload, linked at VA `0x00100000` |
| `Contents/Resources/me.img3` | 379860 | `logo` IMG3 (the blackra1n boot picture) |
| `Contents/Resources/purpled1sk.dmg` | 524288 | HFS+ ramdisk that becomes `/` via `rd=md0` |

The host was built from `/Users/geohot/Desktop/blackra1n/mac/blackra1n/`
(`main.m`, `blackra1n.m`, `ra1n_wrapper.c`). The payload strings identify the
author and the joke: `"geohot"`, `"black is the new purple"`.

This is **not** a BootROM exploit. It compromises **iBoot**, Apple’s
second-stage bootloader, which is loaded from NAND and is replaced on every
firmware update. On devices whose BootROM still had `24kpwn`
(old iPhone 3GS, iPhone 2G/3G, iPod touch 1G/2G), a later boot-chain patch
made the jailbreak persist across reboot. On **new-bootrom 3GS** and **iPod
touch 3G**, iBoot is the only hole, so the jailbreak is **tethered**: you
rerun blackra1n after every reboot.

---

## 2. The boot chain this sits in

```
Power on
  └─ BootROM (immutable)
       └─ LLB  ('illb' IMG3)
            └─ iBoot ('ibot' IMG3)          ← recovery mode, this exploit
                 └─ kernelcache             ← patched in place
                 └─ ramdisk (optional)      ← purpled1sk.dmg, rd=md0
                 └─ device tree, boot-args
```

iBoot on these chips is a small ARM image with:

- an ARM **exception vector table** at virtual address `0`
- a first-level **MMU page table** (1 MB sections) whose base is in `TTBR0`
- a USB stack that implements both the recovery-mode **vendor command**
  channel (`bmRequestType = 0x40`) and a **class** channel
  (`bmRequestType = 0x21` / `0xA1`) used to bulk-in images

The payload’s whole job is: hijack those vectors, keep running after iBoot
recovers, then patch every signed image iBoot is about to boot.

---

## 3. Host side — the USB conversation

The i386 slice of the Mac binary (`ra1n_wrapper.c`) is a thin state machine
driven by MobileDevice’s recovery-mode callback. Once the device is in
recovery, `_internal_recovery_callback` does the following, in order.

### 3.1 Enter recovery

`AMDeviceEnterRecovery` on a normally-booted device. iBoot comes up as USB
`05ac:1281` (iBoot recovery). The UI prints `entering recovery...` /
`go go gadget ra1n`.

### 3.2 `setenv auto-boot true` / `saveenv`

iBoot recovery commands are sent with a **vendor** control transfer:

```
usb_control_msg(dev,
    0x40,          /* Host-to-device | Vendor | Device */
    0,             /* bRequest  */
    0, 0,          /* wValue, wIndex */
    cmd, strlen(cmd),
    1000);
```

`auto-boot true` plus `saveenv` means “when I reset you, don’t sit in
recovery, boot”. That is why the phone reboots itself at the end instead of
waiting for a `go`.

### 3.3 Upload the payload (`bRequest = 1`)

`_send_payload` reads `Contents/Resources/payload` and calls the file sender
at `0x3599`. That routine chops the file into **`0x800`-byte** chunks and,
for each chunk `i`:

```
usb_control_msg(dev, 0x21, 1, i, 0, buf, 0x800, 1000);   /* OUT data */
usb_control_msg(dev, 0xA1, 3, 0, 0, status, 6, 1000);    /* GET_STATUS */
```

`0x21` = Host-to-device | Class | Interface. This is iBoot’s image-receive
path — the same mechanism DFU uses. The bytes land in iBoot’s load buffer:

| SoC | Load address (from the payload’s own device table) |
|---|---|
| S5L8920 (iPhone 3GS) | `0x41000000` |
| S5L8900 / S5L8720    | `0x09000000` |
| S5L8922 (iPod touch 3G) | `0x09000000` |

A short remainder chunk is sent if `len & 0x7FF != 0`, then **three** empty
`0x21/1` packets with `wLength = 0` to flush the USB state machine. The log
line is `sent payload`.

The payload is 9504 bytes, so this is two full `0x800` chunks plus a
`0x520`-byte tail. After this call, the **entire** 9504-byte image sits at
the load address above. Nothing has executed yet.

### 3.4 Fire the bug (`bRequest = 2`)

`_send_exploit` at `0x3513` is four arguments and a zero-length transfer:

```
usb_control_msg(dev,
    0x21,          /* same class pipe as the upload */
    2,             /* bRequest — the buggy handler */
    0, 0,
    NULL, 0,       /* no data stage */
    1000);
```

That is the entire exploit trigger. The log line is `send exploit!!!` /
`sent exploit`. The host then `usleep(300000)` to let iBoot take the
exception and run the stub.

### 3.5 What request 2 does inside iBoot

iBoot’s class-request dispatcher treats `bRequest = 1` as “copy this USB
payload into the load buffer” and `bRequest = 2` as a control operation on
that buffer. The 3.1.x handler for request 2 performs a `memcpy` whose
**destination register is 0** (an unchecked / uninitialized pointer, the
famous `usb_control_msg(0x21, 2)` bug) and whose **length is `0x2000`**.
Source is the load buffer that step 3.3 just filled.

Net effect:

```
memcpy(0x00000000, load_addr, 0x2000);
```

Address 0 is the ARM **exception vector table**. The first 8192 bytes of
the payload — which *are* a vector table plus the stub — now sit where
every exception, IRQ and abort will jump. The remaining
`9504 - 8192 = 1312` bytes of the payload never land on the vector page;
they stay at `load_addr + 0x2000`. The stub’s first job is to get the whole
image into a stable virtual mapping before iBoot’s USB task reclaims the
load buffer.

### 3.6 Picture, ramdisk, reboot

After the 300 ms pause the host continues, now talking to a *patched* iBoot:

| Step | Transfer | Purpose |
|---|---|---|
| `send_command("geohot")` | `0x40` | Kick iBoot’s command loop (and a string the payload knows) |
| upload `me.img3` | `0x21/1` chunks | Boot logo |
| `setpicture 0` | `0x40` | Paint it |
| `bgcolor 1 1 1` | `0x40` | White background |
| upload `purpled1sk.dmg` | `0x21/1` chunks | Jailbreak ramdisk |
| `send_command("geohot")` | `0x40` | Kick the command loop again |
| USB teardown (`0x3472` → `0x3fa7`) | — | Drop the handle; device boots |

Because `auto-boot` was set, iBoot proceeds into `bootx` with the ramdisk
and a kernel the payload has already rewritten. The host prints
`I JUST DROPPED IT LIKE ITS HOT` and `done, wait for reboot`.

---

## 4. The vector page — what now lives at address 0

The first 32 bytes of `payload.bin` are eight ARM branch instructions, one
per exception:

```
0x0000  B exploit_stub     @ reset
0x0004  B exploit_stub     @ undefined instruction
0x0008  B exploit_stub     @ SVC
0x000C  B exploit_stub     @ prefetch abort
0x0010  B exploit_stub     @ data abort
0x0014  B exploit_stub     @ reserved
0x0018  B exploit_stub     @ IRQ
0x001C  B exploit_stub     @ FIQ
0x0020..0x003C  0x00000040  (padding, eight words)
0x0040          exploit_stub
```

The encodings are `EA00000E` … `EA000007`: each branch target is `0x40`.
Whatever exception iBoot takes next — and a USB completion, an abort from
the broken memcpy, or the next IRQ is enough — execution is at `0x40` with
the **interrupted iBoot context** in the registers. `LR` in particular still
holds a return address inside iBoot, which is how the stub tells the SoCs
apart.

---

## 5. `exploit_stub` (`0x40`) — identify, map, relocate

Annotated from the original words at `0x0040`–`0x00A8`:

```
push    {r0-r12, lr}
mov     r0, #0x18
str     r0, [sp, #0x34]          @ fill the SPSR-shaped slot on the stack

mrc     p15, 0, r5, c2, c0, 0    @ TTBR0
lsr     r5, r5, #14
lsl     r5, r5, #14              @ 16 KB-align the first-level table

lsr     r4, lr, #24              @ top byte of the interrupted PC
cmp     r4, #0x4F
moveq   r1, #0x41000000          @ 3GS load address
moveq   r2, #0x42000000          @ 3GS phys for VA 0x00100000
moveq   r3, #0                   @ device id 0
movne   r1, #0x09000000
movne   r2, #0x0A000000
movne   r3, #1                   @ device id 1
cmp     r4, #0x0F
moveq   r3, #2                   @ device id 2 (iPod touch 3G)

str     r3, [r1]                 @ payload[0] at the load address = id
sub     lr, lr, #4
str     lr, [r1, #4]             @ payload[1] = exception PC

orr     r2, r2, #0x1E
orr     r2, r2, #0xC00           @ section descriptor 0xC1E
str     r2, [r5, #4]             @ TTB[1] → VA 0x00100000–0x001FFFFF

mov     r0, #0x00100000
mov     r2, #0x4000
bl      memcpy32                 @ copy 16 KB load_addr → 0x00100000

mov     r0, #0x00100000
add     pc, pc, r0               @ jump into the VA copy
```

### 5.1 Device id from `LR[31:24]`

iBoot is linked at a fixed base per SoC, so the interrupted `LR`’s high byte
is a reliable fingerprint:

| `LR >> 24` | SoC | Device id written to `payload[0]` | iBoot text |
|---|---|---|---|
| `0x4F` | S5L8920 (iPhone 3GS) | 0 | `0x4FF00000` |
| `0x0F` | S5L8922 (iPod touch 3G) | 2 | `0x0FF00000` |
| anything else | S5L8900 / S5L8720 | 1 | `0x18000000` |

The stub **overwrites the first two words of the copy at the load address**
with `(device_id, saved_pc)` before relocating. From this point on,
`*(uint32_t *)0x00100000` *is* the device id. `payload_main` reads it from
there.

### 5.2 The section descriptor

`TTB[1]` is the first-level entry for virtual `0x00100000`. The value stored
is `phys | 0x00000C1E`:

- bits `[1:0] = 0b10` — first-level **section** (1 MB)
- bits `[3:2] = 0b11` — C=1, B=1, write-back cached
- bits `[11:10] = 0b11` — AP = full client access (`0xC00`)
- bit 4 set (the `0x10` in `0x1E`)

Physical bases: `0x42000000` (3GS) or `0x0A000000` (everyone else). After
this store, virtual `0x00100000` is a cached 1 MB window onto the uploaded
image. The payload is built as if it lived at that address — every
PC-relative pool in the blob is an `0x0010xxxx` pointer.

### 5.3 Why copy 16 KB, not 9504 bytes

`0x4000` is larger than the 9504-byte image. The extra
`0x4000 - 0x2520 = 0x1AE0` bytes become the payload’s **BSS** (globals at
`0x00102520` onward). The copy also pulls in the tail of the payload that
the `0x2000`-byte vector overwrite never reached.

`memcpy32` itself is at `0x0130`: word-at-a-time, `dst` in `r0`, `src` in
`r1`, byte length in `r2`.

### 5.4 The `add pc, pc, r0` trick

At the `add` instruction, ARM `PC` is `current + 8`. With `r0 = 0x00100000`
that lands on **`0x001000B4`**, which is the same `stub_after_reloc` that
sits at file offset `0xB4`, now executing from the virtual mapping rather
than from the volatile vector page.

```
0x00B4  bl   payload_main          @ 0x001019AC
0x00B8  mov  r0, #0
0x00BC  ldr  r1, =g_iboot          @ 0x0010256C
        ldr  r1, [r1]
        ldr  r1, [r1, #4]
        mov  r2, #0x40
        bl   memcpy_words          @ restore 64 bytes of vectors at 0
        bl   icache_invalidate     @ MCR p15,0,r0,c7,c5,0  (ICache)
        ldr  lr, [saved]
        pop  {r0-r12, pc}          @ resume iBoot
```

So the stub is **not** a permanent hijack of the vector table. It runs once,
lets `payload_main` plant hooks *inside iBoot*, puts a clean 64-byte vector
page back at address 0 (copied from the per-device pointer at
`device_desc+4`: `0x84000000` on 3GS, `0x22000000` otherwise), flushes the
I-cache, and returns. iBoot thinks the USB request finished normally.

The I-cache routine at `0x0158` is surrounded by `NOP`s (`mov r0, r0`) so
the `MCR` is not on a cache-line boundary — a detail that matters on the
ARM11/Cortex-A8 instruction caches of these SoCs.

---

## 6. The runtime object and the device table

`payload_main` (`0x19AC`) starts by turning the device id into a 20-byte
descriptor from the table at file offset `0x2420`:

```
id * 0x14 + 0x00102420
```

| Offset | id 0 (S5L8920) | id 1 (S5L8900) | id 2 (S5L8922) | Meaning |
|---|---|---|---|---|
| +0x00 | `0x4FF00000` | `0x18000000` | `0x0FF00000` | iBoot text base |
| +0x04 | `0x84000000` | `0x22000000` | `0x22000000` | vector-restore source |
| +0x08 | `0x41000000` | `0x09000000` | `0x09000000` | USB load address |
| +0x0C | `0xBF200000` | `0x38E00000` | `0x38E00000` | live iBoot object |
| +0x10 | `0x00004000` | `0x00080000` | `0xFFFFF1FF` | extra / flags |

It then writes into that live iBoot object:

```
obj = *(device_desc + 0x0C);          /* 0xBF200000 or 0x38E00000 */
BSS->ptr_2568 = obj[0x10/4];
obj[0x14/4]   = device_desc->extra;   /* patches a field iBoot will use */
BSS->iboot    = device_desc;
BSS->device_id = id;                  /* 0x00102538 */
```

From here on, almost every function loads `g_iboot` from `0x0010256C` and
treats `g_iboot->iboot_base` (`+8` in the descriptor, i.e. the USB load
address **or** the iBoot text, depending on which view is live after later
rewrites) as the search window for byte patterns.

BSS occupies `0x00102520`–`0x00104000`. The slots the payload actually uses
as function pointers (`0x2570`, `0x2574`, `0x257C`, `0x2580`, `0x2584`) are
filled by `find_pattern` against iBoot’s own text.

---

## 7. `find_pattern` — the only scanner

Everything that needs an iBoot- or kernel-internal address goes through
`find_pattern` at `0x06C0`. It is deliberately dumb and therefore portable
across the three iBoot builds this payload supports (`iBoot-240.4` on
S5L8900, `iBoot-359.3` on S5L8920):

```
u8 *find_pattern(needle, hay, nlen):
    for p = hay; p < hay + 0x01000000; p += 2:     /* 16 MB, halfword stride */
        for i in 0..nlen-1:
            if needle[i] != 0xFF and needle[i] != p[i]:
                break
        if i == nlen: return p
    return NULL
```

`0xFF` is a wildcard. Matches are typically used as
`handler = match + 1` because iBoot is mostly **Thumb**: the `+1` sets the
Thumb bit so a later `BX` / `BLX` switches modes correctly.

This is why the payload does not contain a pile of per-build absolute
addresses for the patch sites. It contains **signatures**. The 3GS-only
exception is `call_iboot_4FF1E59D` at `0x0194`, which constructs
`0x4FF1E59D` in a register with four `mov`/`lsl`/`orr`s and `BLX`s it —
a Thumb helper inside iBoot-359.3 that was stable enough to hardcode.

---

## 8. What `payload_main` plants

After the device table dance, main does three pattern searches and a call:

1. Find an 8-byte prologue at `0x2398` (`06 ff ff ff ff 68 05 e0`) in
   iBoot text → `BSS->fn_2574 = hit + 1`. This is iBoot’s **command
   lookup / dispatch** stub.
2. Find a second prologue at `0x23A0` → `BSS->fn_2580`.
3. Call `(fn_2574)("ibot", 2)` and stash the returned command object in
   `BSS->fn_257C`. That is how the payload **registers a new iBoot
   command named `ibot`** without knowing the registrar’s address at
   compile time.
4. Fall into `install_runtime_hooks` (`0x1938`), which on S5L8920 pokes
   `0xBF100000` (a control word: `(v & 3) | 1`) and maps VA `0x00200000`
   as another 1 MB section (`map_section_va_00200000` at `0x02D0` writes
   `TTB[2]`). On the other chips it copies a version string into
   `0x00102558` for the later `strcmp` against `"iBoot-240.4"` /
   `"iBoot-359.3"`.

It then returns to the stub, which restores the vectors. iBoot is now
running with:

- a new `ibot` command
- at least one vtable / callback pointer redirected
- its RSA-check sites **not yet** patched — that happens when iBoot next
  *loads an image*, which is what the host is about to make it do
  (picture, ramdisk, kernel)

---

## 9. Image load path — `ibot`, `illb`, `ibot` IMG3s

iBoot loads firmware pieces as **IMG3** containers. The on-disk layout
(little-endian tags, so they appear reversed if you `strings` the payload)
is:

```
'Img3'  magic          0x496d6733     (bytes 33 67 6d 49 = "3gmI")
fullsz, size
'illb' / 'ibot' / ...  type tag
  nested:
    'GABK'  KBAG       0x4B424147     (keybag — AES wrap of the image key)
    'THIS'  TYPE       0x53484954
    'ATAD'  DATA
```

When the hooked load path runs, the payload branches on the type tag.

### 9.1 `handle_illb` (`0x102C`) — Low-Level Bootloader

Used on the S5L8900 path (old devices, where LLB is still in play). It:

1. Calls `install_cmd_handler` (`0x0AE4`) — a second, more aggressive
   command-registrar hook based on the 16-byte Thumb prologue at `0x24A4`
   (`F0 B5 5E 46 55 46 44 46 70 B4 06 AF 9A B0 80 46`, the standard
   `push {r4-r7,lr}; mov r6,lr; …` iBoot function entry).
2. Reads `0x8000` bytes of the LLB image into a scratch buffer at
   `iboot_base` via iBoot’s own read callback (`img+0x1C`).
3. If byte `scratch[0x900]` is already `'F'`, it has been here before and
   returns.
4. Marks `scratch[0x900] = 'F'`, calls `patch_sigchecks(scratch + 0x800)`,
   writes the buffer back through the write callback (`img+0x24`).
5. Repeats for a second IMG3 at file offset `0x20000`: walk KBAG, stamp
   the 4-byte marker `'Rain'` at `+0x241`, patch signature checks, write
   back.

The `'F'` / `'Rain'` stamps are dirty flags so a second pass (tethered
re-entry) is idempotent.

### 9.2 `handle_ibot` (`0x1160`) — iBoot loading iBoot (or iBEC)

This is the 3GS / iPod-3G path and also the “iBoot reloading itself”
path. It `strcmp`s a captured version banner against `"iBoot-240.4"` or
`"iBoot-359.3"` (argument `expect_old` selects which). On match it loops
over IMG3 headers:

- **`'illb'`** — KBAG walk, rewrite size words (`0x00024200`,
  `0x000241EC`), copy 64 bytes of the payload’s own vector trampolines to
  `scratch+0x20000` and 512 bytes of helper code to `scratch+0x24000`,
  then `patch_sigchecks(scratch+0x40)`.
- **`'ibot'`** — KBAG walk, write `'Rain'` at `+0x241`,
  `patch_sigchecks(scratch+0x40)`.
- **`'ertd'`** (the reversed `'dtre'` / device-tree-ish tag the payload
  uses as a ramdisk-command vector) — patch a function pointer at
  `cmd+0xC` so the next `bootx` uses the payload’s copy.

The loop uses iBoot’s own read/write callbacks, so as far as iBoot is
concerned it is just loading a perfectly normal image. The bytes it
actually executes afterwards have had their signature checks neutered.

### 9.3 `img3_patch_kbag` (`0x0978`)

Walks the IMG3 tag list starting at `+0x14`. Each tag is
`{uint32 id, uint32 span, …}`; the walker does `p += span` until it sees
`id == 0` or `id == 'GABK'`. On a KBAG whose claimed header size is
`0x100`, it then scans forward to BSS and replaces every `'THIS'`
(TYPE) word with `0x20000200`. That constant is two Thumb instructions
`movs r0, #0; movs r0, #2` / a check that always looks like “production,
no security domain mismatch” to the verifier. Combined with the RSA-check
patches below, iBoot will decrypt and execute an image that is not Apple-
signed.

### 9.4 `patch_sigchecks` (`0x07E0`) — the RSA hole

This is the payload’s most important byte patch. It searches a 256 KB
window of the image just loaded and overwrites the **RSA / image4-style
verify** sequences that iBoot runs on every IMG3.

**Device id 0 (3GS), 8-byte needle at `0x245C`:**

```
18 bf 01 20 a7 f1 00 0d
```

On hit, the first four bytes are replaced with `00 20 00 20` —
two Thumb `movs r0, #0`. The verify function now returns 0 (success)
immediately. A second scan with the 18-byte needle at `0x246E` then walks
halfwords, writing `0x2200` (`movs r2, #0` / NOP-shaped) until it sees
the sentinel `0x9207`.

**Device id ≠ 0, 10-byte needle at `0x2464`:**

```
01 38 98 43 c0 0f 01 23 58 40
```

Writes `0x2200` at `hit+8`, then a second scan (needle at `0x2480`)
walks until sentinel `0x9208`, writing `0x2200` at `hit+6` each step.

After this, iBoot will load **any** IMG3 the host (or the ramdisk) feeds
it. That is what makes the unsigned `purpled1sk.dmg` and the
on-device `blackra1n.app` possible.

---

## 10. The kernel — `patch_kernel` (`0x1578`)

iBoot’s last act before jumping to XNU is to load the kernelcache. The
payload intercepts that with `load_hook_wrapper` at `0x0290`:

```
push {r7, lr}
mov  r4, r0          @ image
mov  r5, r2          @ length
mov  r6, r1          @ dest / load address
bl   patch_kernel    @ 0x1578
@ then BX to (original_loader | 1)  — Thumb tail-call
```

`patch_kernel` receives the kernel’s load address in `r1` and does four
independent things.

### 10.1 `proc_enforce = 0`

`proc_enforce` is a `sysctl` / MACF knob. When it is non-zero, the MAC
framework enforces codesigning. The payload:

1. `find_pattern("proc_enforce", kbase, 13)` where `kbase` is the kernel
   load address with the low 24 bits cleared (`addr & 0xFF000000`).
2. Builds a tagged pointer `marker = (hit & 0x00FFFFFF) | 0xC0000000`.
3. Scans a 16 MB window for that marker and writes **0** at `match - 0x1C`.

That store is the actual global, not the name string. Doing it by
cross-reference rather than by a hardcoded BSS offset is what lets one
payload hit every 3.1.x kernel this jailbreak supports.

### 10.2 AMFI

Two signatures, selected by device id:

```
old (10 bytes @ 0x2402):  98 47 00 b1 00 24 20 46 90 bd
new (20 bytes @ 0x240C):  33 ff 2f e1 00 00 50 e3 00 00 00 0a 00 40 a0 e3 04 00 a0 e1
```

A single byte at a fixed offset into the hit (`hit[4]` or `hit[12]`) is
set to `1`, which collapses an AMFI “is this signed?” branch into the
allow path. The replacement Thumb stub at `0x23F8` (`kBootxStub`) is a
small `bootx` wrapper: `push {r4,r7,lr}; ldr r3, [pc,#N]; ldr r3, [r3];
blx r3; … pop {r4,r7,pc}` — i.e. “call through a pointer and return”,
skipping the signature gate that originally sat in `bootx`.

### 10.3 Packed kernelcache (LZSS)

3.1.x kernelcaches are Apple **LZSS**-compressed (the same algorithm
`lzssdec` uses: `N = 0x1000`, `F = 0x12`, threshold 2, window primed
with `0x20`). The decompressor is at `0x030C` and is a straight
implementation of that codec; `0xFEE` in the constant pool is `N - F`.

If `img3_patch_kbag(iboot_base)` says the image in the iBoot scratch
area is still a packed kernelcache, `patch_kernel`:

1. `memset(iboot_base + 0x400000, 0, 0x800000)` — 8 MB unpack buffer.
2. Reads a 32-bit length at `iboot_base + 0x50`, **byte-swaps** it
   (`bswap32` at `0x0150`, a single `REV`), and calls
   `lzss_unpack(dst = iboot_base+0x400000, src = iboot_base+0x1C0, len)`.
3. Re-runs the AMFI / `proc_enforce` patches on the **unpacked** image.
4. Calls `relocate_kernelcache` (`0x0B78`), which is a Mach-O slide:
   it builds a 0xFEE-byte workspace, writes `0x20` then `0x1000` into
   translation tables at offsets `0xC40C` / `0x8408` / `0x4004` /
   `0xD424` (those immediates are in the pool next to the function —
   they are Mach-O load-command-shaped constants, not addresses), and
   walks the unpacked image fixing segment filesizes so XNU’s own
   loader accepts the slid cache.
5. Writes the new packed length back (another `bswap32` of
   `iboot_base+0x4C`) and copies the result over the original.

Helpers `0x0430` and `0x05B0` are the LZSS extra-literal / union-find
style tables used by that relocator. They are the least readable part of
the blob; they exist only to make the unpacked kernelcache a well-formed
Mach-O again after the AMFI bytes have changed its size.

### 10.4 `rd=md0`

If the kernelcache was *already* unpacked (the `img3_patch_kbag` early
return), the function takes the short path:

```
hit = find_pattern("rd=md0 ", kbase, 7);
*hit = 0;                                 @ drop the guard / make it match
hit = find_pattern("magic string to crib@#$", kbase, 0x16);
memcpy_words(hit, iboot_base, 0x400000);  @ paste boot-args / ramdisk
```

`rd=md0` is the iBoot/XNU boot-arg that mounts the **ramdisk** (the
image the host just uploaded as `purpled1sk.dmg`) as the root filesystem.
That ramdisk contains the on-device `blackra1n.app`, Cydia bootstrap,
and the `proc_enforce`/AMFI-disabled userland. `"magic string to crib@#$"`
is a unique marker the payload plants so it can find its own boot-arg
block later without scanning for `rd=`.

The string pool at `0x1D38` is the complete set:

```
0x1D38  "iBoot-240.4"
0x1D44  "iBoot-359.3"
0x1D50  "rd=md0 "
0x1D58  "-progress"
0x1D64  "Ramdisk too large"
0x1D78  "magic string to crib@#$"
0x23DC  "fsboot"
0x23E4  "proc_enforce"
0x23F4  "bootx"
```

`"Ramdisk too large"` / `"-progress"` are iBoot messages the payload
matches to find the ramdisk-size check and the progress callback, so it
can lift the size cap (the dmg is 512 KB, but the check is patched
anyway) and keep the USB transfer from stalling.

---

## 11. `prepare_ramdisk_boot` (`0x1A70`) — the vtable hook body

`iboot_hook_entry` at `0x00F4` is the ARM veneer iBoot actually jumps to
once a vtable slot has been redirected. It is a full register save:

```
mov  r3, #0x00100000
add  r3, r3, #8
stm  r3, {r0-r14}                 @ 15 words at payload+8
ldr  r1, =g_iboot
ldr  r1, [r1, #8]                 @ iboot_base
add  sp, r1, #0x02000000          @ scratch stack 32 MB above iBoot
bl   prepare_ramdisk_boot
ldm  r3, {r0-r14}
ldr  pc, [0x00100004]             @ the saved exception PC from the stub
```

`prepare_ramdisk_boot` then:

1. Reads a 32-bit board id at `search_base + 0x208`. If it equals
   `'n82a'` (`0x6132386E` — iPhone 3GS, `n82ap`), it runs
   `hook_crypto_callbacks` (`0x071C`), which pattern-matches two AES/SHA
   prologues (`0x24D8`, `0x24D0`) and redirects those function pointers
   so subsequent IMG3 decrypts go through the payload. 3GS is the only
   device in this set whose iBoot still does per-image AES in a way the
   payload needs to see.
2. Calls the registered `ibot` command object with
   `("ibot", dest=iboot_base+0x20000, src=0x00100000)`.
3. `memcpy_words(0x00000000, iboot_base+0x20000, 0x2000)` — puts a
   *prepared* 8 KB page (not the original exploit stub) onto the vector
   page, then I-cache invalidates.
4. Walks low memory in 4 KB pages up to `0x0002FFFF`, looking for a
   6-word header whose top 12 bits match `iboot->load_base`. On a match
   it walks backwards for a NUL word and plants `BSS->ptr_2568` at
   `header+8` and at `vtable+0x10`. That is how the next iBoot image-write
   callback is permanently redirected.

After this returns, iBoot continues into `bootx` with:

- vectors that belong to the payload’s prepared page
- a ramdisk already in the load buffer
- a kernelcache whose MACF/AMFI/proc_enforce bits will not fire
- `rd=md0` so XNU mounts that ramdisk as `/`

---

## 12. The S5L8900-only Thumb relocator (`0x0250`)

Old devices (iPhone 2G/3G, iPod touch 1G) have a small Thumb function the
3GS path never uses. It takes the high byte of `SP`, treats that as an
iBoot base, and copies 64 KB *downwards* from `base+0x40` over `base+0`,
then `BLX`es `base+0x3969` (a Thumb routine inside that iBoot). This is
the “slide iBoot down over its own header and re-enter” trick that the
open-ra1n reimplementation also had, and it is why the payload carries
both ARM and Thumb entry trampolines:

```
0x01E0  Thumb:  ldr r3, =0x00100290; bx r3     @ load_hook_wrapper (ARM)
0x0200  Thumb:  ldr r1, =0x001006B4; bx r1     @ lzss_thunk (ARM)
0x0250  Thumb:  the 64 KB self-move above
```

The `BX` targets are **even**, so the CPU stays in ARM. The `c046`
halfwords around them are Thumb `mov r8, r8` NOPs for alignment.

---

## 13. Memory map at the moment iBoot is owned

```
VA 0x00000000    exception vectors
                   originally iBoot's; briefly the payload stub;
                   finally a 64-byte restore from device_desc+4,
                   then an 8 KB prepared page from prepare_ramdisk_boot

VA 0x00100000    payload (1 MB section, phys 0x42000000 or 0x0A000000)
                   0x00100000  device id (word)
                   0x00100004  saved exception PC
                   0x00100008  register save area (15 words)
                   0x00100040  exploit_stub (also runs from VA 0 the first time)
                   0x00100290  C payload
                   0x00101D38  string pool
                   0x00102420  device_table[3]
                   0x00102520  BSS / function pointers
                   0x00104000  end of the 16 KB copy

VA 0x00200000    second 1 MB section, mapped by install_runtime_hooks
                   (3GS: TTB[2] written from 0x02D0)

iBoot text       0x4FF00000  (3GS)
                 0x18000000  (S5L8900)
                 0x0FF00000  (iPod touch 3G)

USB load buffer  0x41000000  (3GS)
                 0x09000000  (everyone else)
                   payload lands here first, then a copy is mapped at
                   0x00100000; later the ramdisk lands here too

TTBR0            iBoot's first-level table, 16 KB aligned
                   TTB[1]  →  VA 0x00100000
                   TTB[2]  →  VA 0x00200000  (optional)
```

---

## 14. End-to-end, as a single timeline

```
host                         USB                         iBoot
----                         ---                         -----
AMDeviceEnterRecovery  -->                           iBoot recovery
0x40 "setenv auto-boot true"
0x40 "saveenv"
0x21/1  payload chunks  -->                      memcpy to load_addr
0x21/2  (len=0)         -->                      memcpy(0, load_addr, 0x2000)
                                                 exception → exploit_stub
                                                 TTB[1] = section 0x00100000
                                                 copy 16 KB to VA 0x00100000
                                                 payload_main:
                                                   register "ibot"
                                                   hook vtable
                                                 restore 64 B of vectors
                                                 return to iBoot
usleep(300 ms)
0x40 "geohot"           -->                      command loop (now hooked)
0x21/1  me.img3         -->                      unsigned IMG3 accepted
0x40 "setpicture 0"
0x40 "bgcolor 1 1 1"
0x21/1  purpled1sk.dmg  -->                      ramdisk in load buffer
0x40 "geohot"
                                                 prepare_ramdisk_boot
                                                 patch_kernel
                                                   proc_enforce = 0
                                                   AMFI allow
                                                   LZSS unpack + slide
                                                   rd=md0
                                                 bootx → XNU
                                                 mount ramdisk as /
reboot (auto-boot=true)                          jailbroken userland
```

On **old BootROM** devices the ramdisk also patches LLB so the next
cold boot is already jailbroken (untethered). On **new BootROM** 3GS and
iPod touch 3G, BootROM still verifies LLB, so a reboot loses the iBoot
patches and the user has to rerun the host app (tethered).

---

## 15. How this maps onto the files in this tree

| File | What it is |
|---|---|
| `orig/blackra1n.app` | Unmodified Mac RC3 application |
| `orig/payload.bin` | The 9504-byte ARM blob, as extracted |
| `asm/payload.S` | Word-for-word listing of that blob. `make check` byte-compares equal to `orig/payload.bin`. |
| `src/entry.S` | Readable ARM of §§4–5 (vectors, stub, memcpy, I-cache, vtable veneer, Thumb trampolines) |
| `src/payload.c` | Readable C of §§7–11 (`find_pattern`, LZSS, IMG3, RSA, kernel) |
| `src/blobs.h` | The exact needles and replacement sequences quoted above |
| `include/blackra1n.h` | BSS layout and the function-offset map |

The assembly listing is the ground truth. The C is a decompilation of the
same control flow; it is not expected to compile back into the original
9504 bytes. Where the C outlines the LZSS relocator (`0x0430` / `0x05B0` /
`0x0B78`) instead of unrolling it, the `.word` listing in `asm/payload.S`
is the authoritative form.
