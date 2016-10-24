#ifndef __CR_ASM_TYPES_H__
#define __CR_ASM_TYPES_H__

#include <stdbool.h>
#include <signal.h>
#include <asm/ptrace.h>
#include "images/core.pb-c.h"

#include "asm/page.h"
#include "bitops.h"
#include "asm/int.h"

#include "uapi/std/asm/syscall-types.h"

#define SIGMAX			64
#define SIGMAX_OLD		31

/*
 * Copied from the Linux kernel header arch/arm64/include/uapi/asm/ptrace.h
 *
 * A thread ARM CPU context
 */

typedef struct user_pt_regs user_regs_struct_t;
typedef struct user_fpsimd_state user_fpregs_struct_t;


#define REG_RES(r)		((u64)(r).regs[0])
#define REG_IP(r)		((u64)(r).pc)
#define REG_SYSCALL_NR(r)	((u64)(r).regs[8])

#define user_regs_native(pregs)			true
#define core_is_compat(core)			false

/*
 * Range for task size calculated from the following Linux kernel files:
 *   arch/arm64/include/asm/memory.h
 *   arch/arm64/Kconfig
 *
 * TODO: handle 32 bit tasks
 */
#define TASK_SIZE_MIN (1UL << 39)
#define TASK_SIZE_MAX (1UL << 48)

int munmap(void *addr, size_t length);

static inline unsigned long task_size(void) {
	unsigned long task_size;

	for (task_size = TASK_SIZE_MIN; task_size < TASK_SIZE_MAX; task_size <<= 1)
		if (munmap((void *)task_size, page_size()))
			break;

	return task_size;
}

#define AT_VECTOR_SIZE 40

typedef UserAarch64RegsEntry UserRegsEntry;

#define CORE_ENTRY__MARCH CORE_ENTRY__MARCH__AARCH64

#define CORE_THREAD_ARCH_INFO(core) core->ti_aarch64

#define TI_SP(core) ((core)->ti_aarch64->gpregs->sp)

typedef uint64_t auxv_t;
typedef uint64_t tls_t;

static inline void *decode_pointer(uint64_t v) { return (void*)v; }
static inline uint64_t encode_pointer(void *p) { return (uint64_t)p; }

#endif /* __CR_ASM_TYPES_H__ */
