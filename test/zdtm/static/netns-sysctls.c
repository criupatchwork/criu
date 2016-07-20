#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <regex.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "zdtmtst.h"
#include "randrange.h"

#define PROC_PATH_MAX_LEN 100

/*
 * FIXME: Need to fix sysctls ranges now they are all {0, default}
 * and might add some other r/w in netns sysctls which I don't have
 * on my v4.6 kernel
 */

struct named_sysctl_range {
	char name[PROC_PATH_MAX_LEN];
	struct rand_range rr;
} ranges[] = {
	{"/proc/sys/net/core/somaxconn", {64, 192}},
	{"/proc/sys/net/core/xfrm_acq_expires", {15, 45}},
	{"/proc/sys/net/core/xfrm_aevent_etime", {5, 15}},
	{"/proc/sys/net/core/xfrm_aevent_rseqth", {2, 10}},
	{"/proc/sys/net/core/xfrm_larval_drop", {0, 1}},
	{"/proc/sys/net/ipv4/fwmark_reflect", {0, 1}},
	{"/proc/sys/net/ipv4/icmp_echo_ignore_all", {0, 1}},
	{"/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts", {0, 1}},
	{"/proc/sys/net/ipv4/icmp_errors_use_inbound_ifaddr", {0, 1}},
	{"/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses", {0, 1}},
	{"/proc/sys/net/ipv4/icmp_ratelimit", {0, 1000}},
	{"/proc/sys/net/ipv4/icmp_ratemask", {0, 524287}},
	{"net/ipv4/igmp_link_local_mcast_reports", {0, 1}},
	{"/proc/sys/net/ipv4/igmp_max_memberships", {0, 20}},
	{"/proc/sys/net/ipv4/igmp_max_msf", {0, 10}},
	{"/proc/sys/net/ipv4/igmp_qrv", {0, 2}},
	{"/proc/sys/net/ipv4/ip_default_ttl", {0, 64}},
	{"/proc/sys/net/ipv4/ip_dynaddr", {0, 1}},
	{"/proc/sys/net/ipv4/ip_early_demux", {0, 1}},
	{"/proc/sys/net/ipv4/ip_forward", {0, 1}},
	{"/proc/sys/net/ipv4/ip_forward_use_pmtu", {0, 1}},
	{"/proc/sys/net/ipv4/ip_no_pmtu_disc", {0, 1}},
	{"/proc/sys/net/ipv4/ip_nonlocal_bind", {0, 1}},
	{"/proc/sys/net/ipv4/ipfrag_high_thresh", {0, 4194304}},
	{"/proc/sys/net/ipv4/ipfrag_low_thresh", {0, 3145728}},
	{"/proc/sys/net/ipv4/ipfrag_max_dist", {0, 64}},
	{"/proc/sys/net/ipv4/ipfrag_time", {0, 30}},
	{"/proc/sys/net/ipv4/tcp_base_mss", {0, 1024}},
	{"/proc/sys/net/ipv4/tcp_ecn", {0, 2}},
	{"/proc/sys/net/ipv4/tcp_ecn_fallback", {0, 1}},
	{"/proc/sys/net/ipv4/tcp_fin_timeout", {30, 90}},
	{"/proc/sys/net/ipv4/tcp_fwmark_accept", {0, 1}},
	{"/proc/sys/net/ipv4/tcp_keepalive_intvl", {0, 75}},
	{"/proc/sys/net/ipv4/tcp_keepalive_probes", {0, 9}},
	{"/proc/sys/net/ipv4/tcp_keepalive_time", {0, 7200}},
	{"/proc/sys/net/ipv4/tcp_mtu_probing", {0, 1}},
	{"/proc/sys/net/ipv4/tcp_notsent_lowat", {-1, 128}},
	{"/proc/sys/net/ipv4/tcp_orphan_retries", {0, 10}},
	{"/proc/sys/net/ipv4/tcp_probe_interval", {0, 600}},
	{"/proc/sys/net/ipv4/tcp_probe_threshold", {0, 8}},
	{"/proc/sys/net/ipv4/tcp_reordering", {0, 3}},
	{"/proc/sys/net/ipv4/tcp_retries1", {0, 3}},
	{"/proc/sys/net/ipv4/tcp_retries2", {0, 15}},
	{"/proc/sys/net/ipv4/tcp_syn_retries", {0, 6}},
	{"/proc/sys/net/ipv4/tcp_synack_retries", {0, 5}},
	{"/proc/sys/net/ipv4/tcp_syncookies", {0, 1}},
	{"/proc/sys/net/ipv4/xfrm4_gc_thresh", {0, 2147483647}},
	{"/proc/sys/net/ipv6/anycast_src_echo_reply", {0, 1}},
	{"/proc/sys/net/ipv6/auto_flowlabels", {0, 1}},
	{"/proc/sys/net/ipv6/bindv6only", {0, 1}},
	{"/proc/sys/net/ipv6/flowlabel_consistency", {0, 1}},
	{"/proc/sys/net/ipv6/flowlabel_state_ranges", {0, 1}},
	{"/proc/sys/net/ipv6/fwmark_reflect", {0, 1}},
	{"/proc/sys/net/ipv6/icmp/ratelimit", {0, 1000}},
	{"/proc/sys/net/ipv6/idgen_delay", {0, 1}},
	{"/proc/sys/net/ipv6/idgen_retries", {0, 3}},
	{"/proc/sys/net/ipv6/ip6frag_high_thresh", {0, 4194304}},
	{"/proc/sys/net/ipv6/ip6frag_low_thresh", {0, 3145728}},
	{"/proc/sys/net/ipv6/ip6frag_time", {0, 60}},
	{"/proc/sys/net/ipv6/ip_nonlocal_bind", {0, 1}},
	{"/proc/sys/net/ipv6/route/gc_elasticity", {0, 9}},
	{"/proc/sys/net/ipv6/route/gc_interval", {0, 30}},
	{"/proc/sys/net/ipv6/route/gc_min_interval", {0, 1}},
	{"/proc/sys/net/ipv6/route/gc_min_interval_ms", {0, 500}},
	{"/proc/sys/net/ipv6/route/gc_thresh", {0, 1024}},
	{"/proc/sys/net/ipv6/route/gc_timeout", {0, 60}},
	{"/proc/sys/net/ipv6/route/max_size", {0, 4096}},
	{"/proc/sys/net/ipv6/route/min_adv_mss", {0, 1220}},
	{"/proc/sys/net/ipv6/route/mtu_expires", {0, 600}},
	{"/proc/sys/net/ipv6/xfrm6_gc_thresh", {0, 2147483647}},
	{"/proc/sys/net/netfilter/nf_conntrack_acct", {0, 1}},
	{"/proc/sys/net/netfilter/nf_conntrack_checksum", {0, 1}},
	{"/proc/sys/net/netfilter/nf_conntrack_events", {0, 1}},
	{"/proc/sys/net/netfilter/nf_conntrack_expect_max", {0, 1024}},
	{"/proc/sys/net/netfilter/nf_conntrack_frag6_high_thresh", {0, 4194304}},
	{"/proc/sys/net/netfilter/nf_conntrack_frag6_low_thresh", {0, 3145728}},
	{"/proc/sys/net/netfilter/nf_conntrack_frag6_timeout", {0, 60}},
	{"/proc/sys/net/netfilter/nf_conntrack_generic_timeout", {0, 600}},
	{"/proc/sys/net/netfilter/nf_conntrack_helper", {0, 1}},
	{"/proc/sys/net/netfilter/nf_conntrack_icmp_timeout", {0, 30}},
	{"/proc/sys/net/netfilter/nf_conntrack_icmpv6_timeout", {0, 30}},
	{"/proc/sys/net/netfilter/nf_conntrack_log_invalid", {0, 1}},
	{"/proc/sys/net/netfilter/nf_conntrack_max", {0, 262144}},
	{"/proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal", {0, 1}},
	{"/proc/sys/net/netfilter/nf_conntrack_tcp_loose", {0, 1}},
	{"/proc/sys/net/netfilter/nf_conntrack_tcp_max_retrans", {0, 3}},
	{"/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close", {0, 10}},
	{"/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close_wait", {0, 60}},
	{"/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established", {0, 432000}},
	{"/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_fin_wait", {0, 120}},
	{"/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_last_ack", {0, 30}},
	{"/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_max_retrans", {0, 300}},
	{"/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_syn_recv", {0, 60}},
	{"/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_syn_sent", {0, 120}},
	{"/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_time_wait", {0, 120}},
	{"/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_unacknowledged", {0, 300}},
	{"/proc/sys/net/netfilter/nf_conntrack_timestamp", {0, 1}},
	{"/proc/sys/net/netfilter/nf_conntrack_udp_timeout", {0, 30}},
	{"/proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream", {0, 180}},
	{"/proc/sys/net/unix/max_dgram_qlen", {0, 10}},
};

static int write_net_sysctls_rand(void)
{
	int i;
	int ret = 0;

	for (i = 0; i < ARRAY_SIZE(ranges); i++) {
		FILE *fp;
		int val = irand_range(&ranges[i].rr);

		ret = access(ranges[i].name, W_OK);
		if (ret < 0)
			continue;

		fp = fopen(ranges[i].name, "w");
		if (fp == NULL) {
			pr_perror("Failed to fopen %s", ranges[i].name);
			return -1;
		}

		ret = fprintf(fp, "%d", val);
		if (ret < 0) {
			pr_perror("Failed to set %d to %s", val, ranges[i].name);
			fclose(fp);
			return -1;
		}
		fclose(fp);
	}

	return 0;
}

static int match_pattern(char *string, char *pattern)
{
	int status;
	regex_t re;

	if (regcomp(&re, pattern, REG_NOSUB|REG_EXTENDED) != 0) {
		pr_perror("Failed to regcomp \"%s\"", pattern);
		return 0;
	}

	status = regexec(&re, string, (size_t) 0, NULL, 0);
	regfree(&re);

	if (status != 0) {
		return 0;
	}
	return 1;
}

#define SYSCTL_READ_BUF_SIZE 1024

static int read_net_sysctl(char *name, char **data)
{
	int fd;
	int ret = 0;
	int size;
	char buf[SYSCTL_READ_BUF_SIZE];

	fd = open(name, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", name);
		return fd;
	}

	size = read(fd, buf, SYSCTL_READ_BUF_SIZE);
	if (size < 0) {
		pr_perror("Can't read %s", name);
		ret = -errno;
		goto err;
	}

	*data = malloc((size + 1) * sizeof(char));
	if (!*data) {
		pr_perror("Can't allocate appropriate data buf");
		goto err;
	}

	memcpy(*data, buf, size * sizeof(char));
	(*data)[size] = '\0';
err:
	close(fd);
	return ret;
}

struct named_sysctl {
	char name[PROC_PATH_MAX_LEN];
	char *data;
};

static int free_nss(struct named_sysctl *nss, long unsigned int n_nss) {
	int i;

	if (!nss)
		return 0;

	for (i = 0; i < n_nss; i++)
		if (nss[i].data)
			free(nss[i].data);

	return 0;
}

static int save_sysctls_filtered(char *path, char *filter,
		struct named_sysctl **nss, long unsigned int *n_nss) {

	DIR *dp;
	struct dirent *de;
	int ret = 0;

	dp = opendir(path);
	if (!dp) {
		pr_perror("Failed to open %s", path);
		return -1;
	}

	while ((de = readdir(dp))) {
		char dir[PROC_PATH_MAX_LEN];
		struct stat st;

		if (!strcmp(de->d_name, ".") ||
		    !strcmp(de->d_name, ".."))
			continue;

		/* Skip specified directories */
		if (match_pattern(de->d_name, filter))
			continue;

		sprintf(dir, "%s/%s", path, de->d_name);

		ret = stat(dir, &st);
		if (ret == -1) {
			pr_perror("Failed to stat %s", dir);
			goto err_close;
		} else {
			if (S_ISDIR(st.st_mode)) {
				save_sysctls_filtered(dir, filter,
				                      nss, n_nss);
			} else if (st.st_mode & S_IRUSR &&
				   st.st_mode & S_IWUSR) {
				/*
				 * Need the check above to exclude sysctls like
				 * net.netfilter.nf_conntrack_buckets, which are
				 * readonly
				 */
				struct named_sysctl *ns;

				ns = realloc(*nss, ++(*n_nss) * sizeof(struct named_sysctl));
				if (!ns) {
					(*n_nss)--;
					pr_perror("Failed to realloc");
					return -1;
				}

				*nss = ns;
				ns = &(*nss)[*n_nss - 1];

				sprintf(ns->name, "%s", dir);
				ns->data = NULL;

				ret = read_net_sysctl(ns->name, &ns->data);
				if (ret < 0)
					goto err_close;
			}
		}
	}
err_close:
	closedir(dp);
	return ret;
}

#define SYSCTL_NET_DIR "/proc/sys/net"
#define CONF_OR_NEIGH_OR_IGMPLLMR_FILTER "conf|neigh"

int main(int argc, char **argv)
{
	int ret;
	struct named_sysctl *nss_before = NULL, *nss_after = NULL;
	long unsigned int n_nss_before = 0, n_nss_after = 0;
	int i;

	test_init(argc, argv);

	ret = write_net_sysctls_rand();
	if (ret)
		goto err_free;

	ret = save_sysctls_filtered(SYSCTL_NET_DIR, CONF_OR_NEIGH_OR_IGMPLLMR_FILTER,
			&nss_before, &n_nss_before);
	if (ret)
		goto err_free;

	test_daemon();
	test_waitsig();

	ret = save_sysctls_filtered(SYSCTL_NET_DIR, CONF_OR_NEIGH_OR_IGMPLLMR_FILTER,
			&nss_after, &n_nss_after);
	if (ret)
		goto err_free;

	if (n_nss_before != n_nss_after) {
		fail("Number of net sysctls changed");
		ret = -1;
		goto err_free;
	}

	for (i = 0; i < n_nss_before; i++) {
		if (strcmp(nss_before[i].name, nss_after[i].name)) {
			fail("Sysctl names do not match %s != %s",
			     nss_before[i].name, nss_after[i].name);
			ret = -1;
			goto err_free;
		}

		if (strcmp(nss_before[i].data, nss_after[i].data)) {
			fail("Sysctl %s data do not match %s != %s",
			     nss_before[i].name,
			     nss_before[i].data, nss_after[i].data);
			ret = -1;
			goto err_free;
		}
	}

	pass();
err_free:
	free_nss(nss_before, n_nss_before);
	free_nss(nss_after, n_nss_after);
	return ret;
}
