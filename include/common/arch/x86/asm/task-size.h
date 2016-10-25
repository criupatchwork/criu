#ifndef COMMON_ASM_TASK_SIZE_H__
#define COMMON_ASM_TASK_SIZE_H__

#include "common/page.h"

#ifdef CONFIG_X86_64
# define TASK_SIZE	((1UL << 47) - PAGE_SIZE)
#else
/*
 * Task size may be limited to 3G but we need a
 * higher limit, because it's backward compatible.
 */
# define TASK_SIZE	(0xffffe000)
#endif

static inline unsigned long task_size(void) { return TASK_SIZE; }

#endif /* COMMON_ASM_TASK_SIZE_H__ */
