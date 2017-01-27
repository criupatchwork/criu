#include "common/asm/linkage.h"

/*
 * Adopted from linux kernel, we use REP reature only.
 */

ENTRY(std_memcpy)
	movq %rdi, %rax
	movq %rdx, %rcx
	shrq $3, %rcx
	andl $7, %edx
	rep movsq
	movl %edx, %ecx
	rep movsb
	ret
END(std_memcpy)

ENTRY(std_memset)
	movq %rdi,%r9
	movq %rdx,%rcx
	andl $7,%edx
	shrq $3,%rcx
	/* expand byte value  */
	movzbl %sil,%esi
	movabs $0x0101010101010101,%rax
	imulq %rsi,%rax
	rep stosq
	movl %edx,%ecx
	rep stosb
	movq %r9,%rax
	ret
END(std_memset)
