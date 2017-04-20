#include "common/asm/linkage.h"

	.section .head.text, "ax"
ENTRY(__export_parasite_head_start)
	sub	r2, pc, #8			@ get the address of this instruction

	adr     r0, __export_parasite_cmd
	ldr	r0, [r0]

	adr     r1, parasite_args_ptr
	ldr	r1, [r1]
	add	r1, r1, r2			@ fixup __export_parasite_args

	bl	parasite_service

	/* Guard generates the signal SIGTRAP in Linux */
	bkpt	#0

parasite_args_ptr:
	.long __export_parasite_args

__export_parasite_cmd:
	.long 0
END(__export_parasite_head_start)
