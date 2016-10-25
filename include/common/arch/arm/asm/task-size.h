#ifndef COMMON_ASM_TASK_SIZE_H__
#define COMMON_ASM_TASK_SIZE_H__

#include <unistd.h>
#include <sys/mman.h>

#include "common/page.h"

/*
 * Range for task size calculated from the following Linux kernel files:
 *   arch/arm/include/asm/memory.h
 *   arch/arm/Kconfig (PAGE_OFFSET values in Memory split section)
 */
#define TASK_SIZE_MIN 0x3f000000
#define TASK_SIZE_MAX 0xbf000000
#define SZ_1G 0x40000000

int munmap(void *addr, size_t length);

static inline unsigned long task_size(void)
{
	unsigned long task_size;

	for (task_size = TASK_SIZE_MIN; task_size < TASK_SIZE_MAX; task_size += SZ_1G)
		if (munmap((void *)task_size, page_size()))
			break;

	return task_size;
}

#endif /* COMMON_ASM_TASK_SIZE_H__ */
