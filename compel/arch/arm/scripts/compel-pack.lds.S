OUTPUT_ARCH(arm)
SECTIONS
{
	.crblob 0x0 : {
		*(.head.text)
		*(.text*)
		. = ALIGN(32);
		*(.rodata*)
		. = ALIGN(32);
		*(.got*)
		. = ALIGN(32);
		*(.toc*)
		. = ALIGN(32);
	} =0x00000000,

	/* RW data starts on parasite_cmd, check compel_protect_parasite() */
	. = ALIGN(0x1000);

	.data : {
		*(.compel.data) /* it's parasite_cmd */
		. = ALIGN(32);
		*(.data*)
		. = ALIGN(32);
		*(.bss*)
	}

	/* Parasite args should have 4 bytes align, as we have futex inside. */
	. = ALIGN(4);
	__export_parasite_args = .;

	/DISCARD/ : {
		*(.debug*)
		*(.comment*)
		*(.note*)
		*(.group*)
		*(.eh_frame*)
		*(*)
	}
}
