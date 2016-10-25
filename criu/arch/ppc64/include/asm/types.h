#ifndef __CR_ASM_TYPES_H__
#define __CR_ASM_TYPES_H__

#include <stdbool.h>
#include <signal.h>
#include "images/core.pb-c.h"

#include "page.h"
#include "bitops.h"
#include "task-size.h"
#include "asm/int.h"

#include "uapi/std/asm/syscall-types.h"

#define SIGMAX_OLD	31
#define SIGMAX		64

/*
 * Copied from kernel header arch/powerpc/include/uapi/asm/ptrace.h
 */
typedef struct {
        unsigned long gpr[32];
        unsigned long nip;
        unsigned long msr;
        unsigned long orig_gpr3;        /* Used for restarting system calls */
        unsigned long ctr;
        unsigned long link;
        unsigned long xer;
        unsigned long ccr;
        unsigned long softe;            /* Soft enabled/disabled */
        unsigned long trap;             /* Reason for being here */
        /* N.B. for critical exceptions on 4xx, the dar and dsisr
           fields are overloaded to hold srr0 and srr1. */
        unsigned long dar;              /* Fault registers */
        unsigned long dsisr;            /* on 4xx/Book-E used for ESR */
        unsigned long result;           /* Result of a system call */
} user_regs_struct_t;

#define NVSXREG	32

#define USER_FPREGS_FL_FP	0x00001
#define USER_FPREGS_FL_ALTIVEC	0x00002
#define USER_FPREGS_FL_VSX	0x00004
#define USER_FPREGS_FL_TM	0x00010

typedef struct {
	uint64_t fpregs[NFPREG];
	__vector128 vrregs[NVRREG];
	uint64_t vsxregs[NVSXREG];

	int flags;
	struct tm_regs {
		int flags;
		struct {
			uint64_t tfhar, texasr, tfiar;
		} tm_spr_regs;
		user_regs_struct_t regs;
		uint64_t fpregs[NFPREG];
		__vector128 vrregs[NVRREG];
		uint64_t vsxregs[NVSXREG];
	} tm;
} user_fpregs_struct_t;


typedef UserPpc64RegsEntry UserRegsEntry;

#define CORE_ENTRY__MARCH	CORE_ENTRY__MARCH__PPC64

#define REG_RES(regs)           ((u64)(regs).gpr[3])
#define REG_IP(regs)            ((u64)(regs).nip)
#define REG_SYSCALL_NR(regs)    ((u64)(regs).gpr[0])

#define user_regs_native(pregs)			true
#define core_is_compat(core)			false

#define CORE_THREAD_ARCH_INFO(core) core->ti_ppc64

/*
 * Copied from the following kernel header files :
 * 	include/linux/auxvec.h
 *	arch/powerpc/include/uapi/asm/auxvec.h
 *	include/linux/mm_types.h
 */
#define AT_VECTOR_SIZE_BASE 20
#define AT_VECTOR_SIZE_ARCH 6
#define AT_VECTOR_SIZE (2*(AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1))

typedef uint64_t auxv_t;

/* Not used but the structure parasite_dump_thread needs a tls_t field */
typedef uint64_t tls_t;

static inline void *decode_pointer(uint64_t v) { return (void*)v; }
static inline uint64_t encode_pointer(void *p) { return (uint64_t)p; }

#endif /* __CR_ASM_TYPES_H__ */
