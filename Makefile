# Recreate the blackra1n RC3 ARM payload.
#
#   make orig.bin     - reassembles asm/payload.S to a raw image
#   make c            - builds the C reconstruction (freestanding ARM)
#   make check        - orig.bin must match orig/payload.bin
#
# asm/payload.S is a word-for-word listing of orig/payload.bin; `make check`
# requires a byte match. src/payload.c is a readable decompilation of the
# same blob and is not expected to assemble back to the original bytes.
#
# Narrative: docs/HOW_IT_WORKS.md

CROSS   ?= arm-linux-gnueabi-
AS      := $(CROSS)as
CC      := $(CROSS)gcc
LD      := $(CROSS)ld
OBJCOPY := $(CROSS)objcopy

ASFLAGS := -march=armv6
CFLAGS  := -ffreestanding -nostdlib -fno-builtin -Os -marm -march=armv6 \
           -Iinclude -Isrc -Wall -Wno-unused-function
LDFLAGS := -T src/payload.ld

.PHONY: all orig.bin c check clean

all: orig.bin c check

orig.bin: asm/payload.S
	$(AS) $(ASFLAGS) -o /tmp/payload.o asm/payload.S
	$(OBJCOPY) -O binary /tmp/payload.o orig.bin

c: src/entry.S src/payload.c
	$(CC) $(CFLAGS) -c src/entry.S -o /tmp/entry.o
	$(CC) $(CFLAGS) -c src/payload.c -o /tmp/payload.o
	$(LD) $(LDFLAGS) -o payload.elf /tmp/entry.o /tmp/payload.o
	$(OBJCOPY) -O binary payload.elf payload_c.bin

check: orig.bin
	@cmp -s orig.bin orig/payload.bin && echo "orig.bin matches orig/payload.bin" \
	    || (echo "MISMATCH"; cmp -l orig.bin orig/payload.bin | head; exit 1)

clean:
	rm -f orig.bin payload.elf payload_c.bin /tmp/payload.o /tmp/entry.o
