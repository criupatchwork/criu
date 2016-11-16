#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/stat.h>

#include <netinet/ip.h>
#include <arpa/inet.h>

#include <limits.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc		= "Test RAW sockets (IPv4,6)\n";
const char *test_author		= "Cyrill Gorcunov <gorcunov@openvz.org";

#ifndef SO_IP_SET
# define SO_IP_SET		83
#endif

#ifndef IP_SET_OP_VERSION
# define IP_SET_OP_VERSION	0x00000100	/* Ask kernel version */
#endif

struct ip_set_req_version {
	unsigned int	op;
	unsigned int	version;
};

int main(int argc, char *argv[])
{
	struct ip_set_req_version req_version;
	socklen_t size = sizeof(req_version);

	int sk_raw, sk6_raw, res;
	int sk_tcp, sk_udp;

	test_init(argc, argv);

	sk_raw = socket(PF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_RAW);
	if (sk_raw < 0) {
		pr_perror("Can't create IPv4 raw socket");
		exit(1);
	}

	/* Simply to make sure it can be recreated on restore */
	sk6_raw = socket(PF_INET6, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_RAW);
	if (sk6_raw < 0) {
		pr_perror("Can't create IPv6 raw socket");
		exit(1);
	}

	sk_tcp = socket(PF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_TCP);
	if (sk_tcp < 0) {
		pr_perror("Can't create IPv4 raw-tcp socket");
		exit(1);
	}

	sk_udp = socket(PF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_UDP);
	if (sk_udp < 0) {
		pr_perror("Can't create IPv4 raw-udp socket");
		exit(1);
	}

	test_daemon();
	test_waitsig();

	req_version.op = IP_SET_OP_VERSION;
	res = getsockopt(sk_raw, SOL_IP, SO_IP_SET, &req_version, &size);
	if (res) {
		pr_perror("xt_set getsockopt");
	} else
		test_msg("SO_IP_SET version = %d\n", req_version.version);

	pass();
	return 0;
}
