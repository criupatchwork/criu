#ifndef COMMON_ASM_TASK_SIZE_H__
#define COMMON_ASM_TASK_SIZE_H__

/*
 * Copied for the Linux kernel arch/powerpc/include/asm/processor.h
 *
 * NOTE: 32bit tasks are not supported.
 */
#define TASK_SIZE_USER64 (0x0000400000000000UL)
#define TASK_SIZE TASK_SIZE_USER64

static inline unsigned long task_size(void) { return TASK_SIZE; }

#endif /* COMMON_ASM_TASK_SIZE_H__ */
