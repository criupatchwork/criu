#ifndef __CR_PARASITE_COMPAT_H__
#define __CR_PARASITE_COMPAT_H__

/* XXX: define _compat types per-arch */

#ifndef __ASSEMBLY__

#include "images/core.pb-c.h"

#if !defined(CONFIG_X86_64) && !defined(CONFIG_X86_32)
#define rt_sigaction_t_compat rt_sigaction_t
#endif

struct parasite_dump_sa_args_compat {
	rt_sigaction_t_compat sas[SIGMAX];
};

struct parasite_timeval_compat {
	u32	tv_sec;
	u32	tv_usec;
};

struct parasite_itimerval_compat {
	struct parasite_timeval_compat it_interval;
	struct parasite_timeval_compat it_value;
};

struct parasite_dump_itimers_args_compat {
	struct parasite_itimerval_compat real;
	struct parasite_itimerval_compat virt;
	struct parasite_itimerval_compat prof;
};

struct parasite_timespec_compat {
	u32	tv_sec;
	u32	tv_nsec;
};

struct parasite_itimerspec_compat {
	struct parasite_timespec_compat it_interval;
	struct parasite_timespec_compat it_value;
};

struct posix_timer_compat {
	s32 it_id;
	struct parasite_itimerspec_compat val;
	s32 overrun;
};

struct parasite_dump_posix_timers_args_compat {
	s32 timer_n;
	struct posix_timer_compat timer[0];
};

static inline int posix_timers_compat_dump_size(int timer_n)
{
	return sizeof(s32) + sizeof(struct posix_timer_compat) * timer_n;
}

typedef struct {
	u32	ss_sp;
	s32	ss_flags;
	u32	ss_size;
} stack_t_compat;

#endif /* !__ASSEMBLY__ */

#endif /* __CR_PARASITE_COMPAT_H__ */
