#ifndef __CR_SYSCTL_H__
#define __CR_SYSCTL_H__

struct sysctl_req {
	char	*name;
	void	*arg;
	int	type;
	int	flags;
};

extern int sysctl_op(struct sysctl_req *req, size_t nr_req, int op, unsigned int ns);
extern int prepare_sysctl_requests_filtered(char *path, char *filter,
		struct sysctl_req **reqs, size_t *n_reqs);
extern void free_sysctl_requests(struct sysctl_req *reqs, size_t n_reqs);

enum {
	CTL_READ,
	CTL_WRITE,
};

#define CTL_SHIFT	4	/* Up to 16 types */

#define CTL_U32		1	/* Single u32 */
#define CTL_U64		2	/* Single u64 */
#define __CTL_U32A	3	/* Array of u32 */
#define __CTL_U64A	4	/* Array of u64 */
#define __CTL_STR	5	/* String */
#define CTL_32		6	/* Single s32 */

#define CTL_U32A(n)	(__CTL_U32A | ((n)   << CTL_SHIFT))
#define CTL_U64A(n)	(__CTL_U64A | ((n)   << CTL_SHIFT))
#define CTL_STR(len)	(__CTL_STR  | ((len) << CTL_SHIFT))

#define CTL_LEN(t)	((t) >> CTL_SHIFT)
#define CTL_TYPE(t)	((t) & ((1 << CTL_SHIFT) - 1))

/*
 * Some entries might be missing mark them as optional.
 */
#define CTL_FLAGS_OPTIONAL	1
#define CTL_FLAGS_HAS		2
#define CTL_FLAGS_READ_EIO_SKIP	4

/*
 * Max sysctl path is 70 chars:
 * "/proc/sys/net/ipv4/conf/virbr0-nic/igmpv2_unsolicited_report_interval"
 */
#define PROC_PATH_MAX_LEN 100
/*
 * We have only two sysctls longer than 256:
 * /proc/sys/dev/cdrom/info - CDROM_STR_SIZE=1000
 * /proc/sys/net/ipv4/tcp_allowed_congestion_control - TCP_CA_BUF_MAX=2048
 * first one is readonly and second is hostonly
 */
#define PROC_ARG_MAX_LEN 257

#endif /* __CR_SYSCTL_H__ */
