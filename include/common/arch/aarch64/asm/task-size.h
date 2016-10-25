#ifndef COMMON_ASM_TASK_SIZE_H__
#define COMMON_ASM_TASK_SIZE_H__

#include <unistd.h>
#include <sys/mman.h>

#include "common/page.h"

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

#endif /* COMMON_ASM_TASK_SIZE_H__ */
