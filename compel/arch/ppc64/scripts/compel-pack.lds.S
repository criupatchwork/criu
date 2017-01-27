OUTPUT_ARCH(powerpc:common64)
SECTIONS
{
	.text : {
		*(.head.text)
		*(.text*)
		*(.compel.exit)
		*(.compel.init)
	}

	.rodata : {
		*(.rodata*)
		*(.got*)
	}

	.toc : ALIGN(8) {
		*(.toc*)
	}

	/* RW data starts on parasite_cmd, check compel_protect_parasite() */
	. = ALIGN(0x1000);
	.data : {
		*(.compel.data) /* it's parasite_cmd */
		*(.data*)
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
	}
}
