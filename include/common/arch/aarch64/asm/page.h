#ifndef __CR_ASM_PAGE_H__
#define __CR_ASM_PAGE_H__

#include <unistd.h>
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
#define page_size()	sysconf(_SC_PAGESIZE)

/*
 * Range for task size calculated from the following Linux kernel files:
 *   arch/arm64/include/asm/memory.h
 *   arch/arm64/Kconfig
 *
 * TODO: handle 32 bit tasks
 */
#define TASK_SIZE_MIN (1UL << 39)
#define TASK_SIZE_MAX (1UL << 48)

static inline unsigned long task_size(void)
{
	unsigned long task_size;

	for (task_size = TASK_SIZE_MIN; task_size < TASK_SIZE_MAX; task_size <<= 1)
		if (munmap((void *)task_size, page_size()))
			break;
	return task_size;
}

#endif /* __CR_ASM_PAGE_H__ */
