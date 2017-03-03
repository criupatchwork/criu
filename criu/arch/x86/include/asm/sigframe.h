#ifndef UAPI_COMPEL_ASM_SIGFRAME_H__
#define UAPI_COMPEL_ASM_SIGFRAME_H__

#include <stdint.h>
#include <stdbool.h>

#include "asm/fpu.h"

#define SIGFRAME_MAX_OFFSET 8

struct rt_sigcontext {
	unsigned long			r8;
	unsigned long			r9;
	unsigned long			r10;
	unsigned long			r11;
	unsigned long			r12;
	unsigned long			r13;
	unsigned long			r14;
	unsigned long			r15;
	unsigned long			rdi;
	unsigned long			rsi;
	unsigned long			rbp;
	unsigned long			rbx;
	unsigned long			rdx;
	unsigned long			rax;
	unsigned long			rcx;
	unsigned long			rsp;
	unsigned long			rip;
	unsigned long			eflags;
	unsigned short			cs;
	unsigned short			gs;
	unsigned short			fs;
	unsigned short			ss;
	unsigned long			err;
	unsigned long			trapno;
	unsigned long			oldmask;
	unsigned long			cr2;
	void				*fpstate;
	unsigned long			reserved1[8];
};

struct rt_sigcontext_32 {
	uint32_t			gs;
	uint32_t			fs;
	uint32_t			es;
	uint32_t			ds;
	uint32_t			di;
	uint32_t			si;
	uint32_t			bp;
	uint32_t			sp;
	uint32_t			bx;
	uint32_t			dx;
	uint32_t			cx;
	uint32_t			ax;
	uint32_t			trapno;
	uint32_t			err;
	uint32_t			ip;
	uint32_t			cs;
	uint32_t			flags;
	uint32_t			sp_at_signal;
	uint32_t			ss;

	uint32_t			fpstate;
	uint32_t			oldmask;
	uint32_t			cr2;
};

#include "sigframe-common.h"

/*
 * XXX: move declarations to generic sigframe.h or sigframe-compat.h
 *      when (if) other architectures will support compatible C/R
 */

typedef u32			compat_uptr_t;
typedef u32			compat_size_t;
typedef u32			compat_sigset_word;

#define _COMPAT_NSIG		64
#define _COMPAT_NSIG_BPW	32
#define _COMPAT_NSIG_WORDS	(_COMPAT_NSIG / _COMPAT_NSIG_BPW)

typedef struct {
	compat_sigset_word	sig[_COMPAT_NSIG_WORDS];
} compat_sigset_t;

typedef struct compat_siginfo {
	int	si_signo;
	int	si_errno;
	int	si_code;
	int	_pad[128/sizeof(int) - 3];
} compat_siginfo_t;

static inline void __always_unused __check_compat_sigset_t(void)
{
	BUILD_BUG_ON(sizeof(compat_sigset_t) != sizeof(k_rtsigset_t));
}

#ifdef CONFIG_X86_32
#define rt_sigframe_ia32		rt_sigframe
#endif

typedef struct compat_sigaltstack {
	compat_uptr_t		ss_sp;
	int			ss_flags;
	compat_size_t		ss_size;
} compat_stack_t;

struct ucontext_ia32 {
	unsigned int		uc_flags;
	unsigned int		uc_link;
	compat_stack_t		uc_stack;
	struct rt_sigcontext_32	uc_mcontext;
	k_rtsigset_t		uc_sigmask; /* mask last for extensibility */
};

struct rt_sigframe_ia32 {
	uint32_t		pretcode;
	int32_t			sig;
	uint32_t		pinfo;
	uint32_t		puc;
#ifdef CONFIG_X86_64
	compat_siginfo_t	info;
#else
	struct rt_siginfo	info;
#endif
	struct ucontext_ia32	uc;
	char			retcode[8];

	/* fp state follows here */
	fpu_state_t		fpu_state;
};

#ifdef CONFIG_X86_64
struct rt_sigframe_64 {
	char			*pretcode;
	struct rt_ucontext	uc;
	struct rt_siginfo	info;

	/* fp state follows here */
	fpu_state_t		fpu_state;
};

struct rt_sigframe {
	union {
		struct rt_sigframe_ia32	compat;
		struct rt_sigframe_64	native;
	};
	bool is_native;
};

#define RT_SIGFRAME_UC_SIGMASK(rt_sigframe)				\
	((rt_sigframe->is_native)			?		\
	(&rt_sigframe->native.uc.uc_sigmask) :				\
	(&rt_sigframe->compat.uc.uc_sigmask))

#define RT_SIGFRAME_REGIP(rt_sigframe)					\
	((rt_sigframe->is_native)			?		\
	(rt_sigframe)->native.uc.uc_mcontext.rip :			\
	(rt_sigframe)->compat.uc.uc_mcontext.ip)

#define RT_SIGFRAME_FPU(rt_sigframe)					\
	((rt_sigframe->is_native)			?		\
	(&(rt_sigframe)->native.fpu_state)		:		\
	 (&(rt_sigframe)->compat.fpu_state))

#define RT_SIGFRAME_HAS_FPU(rt_sigframe) (RT_SIGFRAME_FPU(rt_sigframe)->has_fpu)

/*
 * Sigframe offset is different for native/compat tasks.
 * Offsets calculations one may see at kernel:
 * - compatible is in sys32_rt_sigreturn at arch/x86/ia32/ia32_signal.c
 * - native is in sys_rt_sigreturn at arch/x86/kernel/signal.c
 */
#define RT_SIGFRAME_OFFSET(rt_sigframe)	((rt_sigframe->is_native) ? 8 : 4 )

#define ARCH_RT_SIGRETURN(new_sp)					\
	asm volatile(							\
		     "movq %0, %%rax				    \n"	\
		     "movq %%rax, %%rsp				    \n"	\
		     "movl $"__stringify(__NR_rt_sigreturn)", %%eax \n" \
		     "syscall					    \n"	\
		     :							\
		     : "r"(new_sp)					\
		     : "rax","rsp","memory")
#else /* CONFIG_X86_64 */
#define RT_SIGFRAME_UC(rt_sigframe) (&rt_sigframe->uc)
#define RT_SIGFRAME_OFFSET(rt_sigframe)	4
#define RT_SIGFRAME_REGIP(rt_sigframe)					\
	(unsigned long)(rt_sigframe)->uc.uc_mcontext.ip
#define RT_SIGFRAME_FPU(rt_sigframe) (&(rt_sigframe)->fpu_state)
#define RT_SIGFRAME_HAS_FPU(rt_sigframe) (RT_SIGFRAME_FPU(rt_sigframe)->has_fpu)

#define ARCH_RT_SIGRETURN(new_sp)					\
	asm volatile(							\
		     "movl %0, %%eax				    \n"	\
		     "movl %%eax, %%esp				    \n"	\
		     "movl $"__stringify(__NR_rt_sigreturn)", %%eax \n" \
		     "int $0x80					    \n"	\
		     :							\
		     : "r"(new_sp)					\
		     : "eax","esp","memory")
#endif /* CONFIG_X86_64 */

int sigreturn_prep_fpu_frame(struct rt_sigframe *sigframe,
		struct rt_sigframe *rsigframe);

#endif /* UAPI_COMPEL_ASM_SIGFRAME_H__ */
