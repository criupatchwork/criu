#ifndef __COMPEL_INFECT_PRIV_H__
#define __COMPEL_INFECT_PRIV_H__

#include <stdbool.h>
#include <signal.h>

#define BUILTIN_SYSCALL_SIZE	8

struct thread_ctx {
	k_rtsigset_t		sigmask;
	user_regs_struct_t	regs;
};

/* parasite control block */
struct parasite_ctl {
	int			rpid;					/* Real pid of the victim */
	void			*remote_map;
	void			*local_map;
	void			*sigreturn_addr;			/* A place for the breakpoint */
	unsigned long		map_length;

	struct infect_ctx	ictx;

	/* thread leader data */
	bool			daemonized;

	struct thread_ctx	orig;

	void			*rstack;				/* thread leader stack*/
	struct rt_sigframe	*sigframe;
	struct rt_sigframe	*rsigframe;				/* address in a parasite */

	stack_t			*thread_sas;
	stack_t			*r_thread_sas;				/* per-thread sas storage (shared) */
	void			*r_thread_stack;			/* stack for non-leader threads (shared) */

	unsigned long		parasite_ip;				/* service routine start ip */

	unsigned int		*addr_cmd;				/* addr for command */
	void			*addr_args;				/* address for arguments */
	unsigned long		args_size;
	int			tsock;					/* transport socket for transferring fds */

	struct parasite_blob_desc pblob;
};

struct parasite_thread_ctl {
	int			tid;
	struct parasite_ctl	*ctl;
	struct thread_ctx	th;
	stack_t			sas;
};

#define MEMFD_FNAME	"CRIUMFD"
#define MEMFD_FNAME_SZ	sizeof(MEMFD_FNAME)

struct ctl_msg;
int parasite_wait_ack(int sockfd, unsigned int cmd, struct ctl_msg *m);

extern void parasite_setup_regs(unsigned long new_ip, void *stack, user_regs_struct_t *regs);
extern void *remote_mmap(struct parasite_ctl *ctl,
		void *addr, size_t length, int prot,
		int flags, int fd, off_t offset);
extern bool arch_can_dump_task(struct parasite_ctl *ctl);
extern int get_task_regs(pid_t pid, user_regs_struct_t *regs, save_regs_t save, void *arg);
extern int arch_fetch_sas(struct parasite_ctl *ctl, struct rt_sigframe *s);
extern int sigreturn_prep_regs_plain(struct rt_sigframe *sigframe,
				     user_regs_struct_t *regs,
				     user_fpregs_struct_t *fpregs);
extern int sigreturn_prep_fpu_frame_plain(struct rt_sigframe *sigframe,
					  struct rt_sigframe *rsigframe);
extern int compel_execute_syscall(struct parasite_ctl *ctl,
		user_regs_struct_t *regs, const char *code_syscall);
#endif
