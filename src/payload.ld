OUTPUT_FORMAT("elf32-littlearm")
OUTPUT_ARCH(arm)
ENTRY(_start)

SECTIONS
{
    . = 0x00100000;
    .text : {
        *(.text)
        *(.text.*)
        *(.rodata)
        *(.rodata.*)
        *(.data)
        . = 0x2520;
    }
    .bss : {
        *(.bss)
        *(.bss.*)
        . = 0x4000;
    }
}
