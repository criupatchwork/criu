/*
 * Please add here type definitions if
 * syscall prototypes need them.
 */

#ifndef COMPEL_SYSCALL_TYPES_H__
#define COMPEL_SYSCALL_TYPES_H__

#include <arpa/inet.h>
#include <sys/time.h>
#include <stdbool.h>
#include <signal.h>
#include <stdint.h>
#include <sched.h>
#include <fcntl.h>
#include <time.h>

#include "common/bitsperlong.h"

struct cap_header {
	uint32_t version;
	int pid;
};

struct cap_data {
	uint32_t eff;
	uint32_t prm;
	uint32_t inh;
};

struct robust_list_head;
struct file_handle;
struct itimerspec;
struct io_event;
struct sockaddr;
struct timespec;
struct siginfo;
struct msghdr;
struct rusage;
struct iocb;

typedef unsigned long aio_context_t;

#ifndef F_GETFD
# define F_GETFD 1
#endif

struct krlimit {
	unsigned long rlim_cur;
	unsigned long rlim_max;
};

/* Type of timers in the kernel.  */
typedef int kernel_timer_t;

#include <compel/plugins/std/asm/syscall-types.h>


extern long sys_preadv_raw(int fd, struct iovec *iov, unsigned long nr, unsigned long pos_l, unsigned long pos_h);

#ifndef BITS_PER_LONG
# error "BITS_PER_LONG isn't defined"
#endif

#if BITS_PER_LONG == 64
#define LO_HI_LONG(val) (val), 0
# else
#define LO_HI_LONG(val) (long) (val), (((uint64_t) (val)) >> 32)
#endif

static inline long sys_preadv(int fd, struct iovec *iov, unsigned long nr, off_t off)
{
	return sys_preadv_raw(fd, iov, nr, LO_HI_LONG(off));
}

#endif /* COMPEL_SYSCALL_TYPES_H__ */
