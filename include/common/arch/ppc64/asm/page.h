#ifndef __CR_ASM_PAGE_H__
#define __CR_ASM_PAGE_H__

#include <unistd.h>

/*
 * Default config for Pseries is to use 64K pages.
 * See kernel file arch/powerpc/configs/pseries_*defconfig
 */
#ifndef PAGE_SHIFT
# define PAGE_SHIFT	16
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
 * Copied for the Linux kernel arch/powerpc/include/asm/processor.h
 *
 * NOTE: 32bit tasks are not supported.
 */
#define TASK_SIZE_USER64	(0x0000400000000000UL)
#define TASK_SIZE		TASK_SIZE_USER64

static inline unsigned long task_size(void) { return TASK_SIZE; }

#endif /* __CR_ASM_PAGE_H__ */
