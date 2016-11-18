#ifndef __CR_ASM_PAGE_H__
#define __CR_ASM_PAGE_H__

#include <sys/mman.h>

#ifndef PAGE_SHIFT
# define PAGE_SHIFT	12
#endif

#ifndef PAGE_SIZE
# define PAGE_SIZE	(1UL << PAGE_SHIFT)
#endif

#ifndef PAGE_MASK
# define PAGE_MASK	(~(PAGE_SIZE - 1))
#endif

#define PAGE_PFN(addr)	((addr) / PAGE_SIZE)
#define page_size()	PAGE_SIZE
/*
 * Range for task size calculated from the following Linux kernel files:
 *   arch/arm/include/asm/memory.h
 *   arch/arm/Kconfig (PAGE_OFFSET values in Memory split section)
 */
#define TASK_SIZE_MIN		0x3f000000
#define TASK_SIZE_MAX		0xbf000000
#define SZ_1G			0x40000000

static inline unsigned long task_size(void)
{
	unsigned long task_size;

	for (task_size = TASK_SIZE_MIN; task_size < TASK_SIZE_MAX; task_size += SZ_1G)
		if (munmap((void *)task_size, page_size()))
			break;

	return task_size;
}

#endif /* __CR_ASM_PAGE_H__ */
