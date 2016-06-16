#define _GNU_SOURCE
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mman.h>

#include "lock.h"
#include "zdtmtst.h"

/* Based on socket_snd_addr test */
const char *test_doc	= "Check that sender addresses are restored correctly";
const char *test_author	= "Kirill Tkhai <ktkhai@virtuozzo.com";

#define SK_SRV "\0socket_snd_srv"
#define SK_NAMEA "\0A-socket_snd_clnt"
#define SK_NAMEB "\0B-socket_snd_clnt"

char *sk_names[3] = {
		SK_NAMEA,
		SK_NAMEB,
		NULL,
	};

#define MSG "hello"

static inline int sk_name_len(const char *name)
{
	if (!name)
		return 0;
	/* '\0' prefix and '\0' postfix */
	return 1 + strlen(name + 1) + 1;
}

static int do_client(int clnt[], mutex_t *lock)
{
	int i;

	for (i = 0; i < 6; i++) {
		if (send(clnt[i%3], MSG, sizeof(MSG), 0) != sizeof(MSG)) {
			pr_perror("write");
			return 1;
		}
	}

	mutex_unlock(lock);
	test_waitsig();
	return 0;
}

int main(int argc, char **argv)
{
	struct sockaddr_un addr;
	unsigned int addrlen;
	int srv, clnt[3] = {-1, -1, -1}, ret, i, status;
	char buf[1024];
	struct iovec iov = {
			.iov_base = &buf,
			.iov_len = sizeof(buf),
		};
	struct msghdr hdr = {
			.msg_name = &addr,
			.msg_namelen = sizeof(addr),
			.msg_iov = &iov,
			.msg_iovlen = 1,
		};
	mutex_t *lock;
	pid_t pid;

	lock = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (lock == MAP_FAILED)
		return 1;

	test_init(argc, argv);
	mutex_init(lock);
	mutex_lock(lock);

	srv = socket(PF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (srv < 0) {
		fail("socket");
		exit(1);
	}

	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, SK_SRV, sizeof(SK_SRV));
	addrlen = sizeof(addr.sun_family) + sizeof(SK_SRV);

	if (bind(srv, &addr, addrlen)) {
		fail("bind\n");
		exit(1);
	}

	for (i = 0; i < 3; i++) {
		clnt[i] = socket(PF_UNIX, SOCK_DGRAM, 0);

		if (sk_names[i]) {
			addr.sun_family = AF_UNIX;
			memcpy(addr.sun_path, sk_names[i], sk_name_len(sk_names[i]));
			addrlen = sizeof(addr.sun_family) + sk_name_len(sk_names[i]);;

			if (bind(clnt[i], &addr, addrlen)) {
				fail("bind\n");
				exit(1);
			}
		}

		memcpy(addr.sun_path, SK_SRV, sizeof(SK_SRV));
		addrlen = sizeof(addr.sun_family) + sizeof(SK_SRV);
		if (connect(clnt[i], &addr, addrlen)) {
			fail("connect\n");
			exit(1);
		}
	}

	pid = fork();
	if (pid == 0) {
		close(srv);
		exit(do_client(clnt, lock));
	} else if (pid != -1) {
		for (i = 0; i < 2; i++)
			close(clnt[i]);
	} else {
		fail("fork");
		exit(1);
	}

	mutex_lock(lock);
	test_daemon();
	test_waitsig();

	kill(pid, SIGTERM);

	if (wait(&status) != pid) {
		fail("wait");
		exit(1);
	}

	if (status != 0) {
		fail("%d:%d:%d:%d", WIFEXITED(status), WEXITSTATUS(status),
				    WIFSIGNALED(status), WTERMSIG(status));
		return 1;
	}

	for (i = 0; i < 6; i++) {
		const char *sk_name = sk_names[i % 3];
		hdr.msg_namelen = sizeof(addr);
		memset(addr.sun_path, 0, sizeof(addr.sun_path));
		ret = recvmsg(srv, &hdr, MSG_DONTWAIT);
		buf[ret > 0 ? ret : 0] = 0;
		if (ret != sizeof(MSG)) {
			fail("%d: %s", ret, buf);
			return 1;
		}

		if (!sk_name && !hdr.msg_namelen)
			continue;
		if (hdr.msg_namelen != sk_name_len(sk_name) + sizeof(addr.sun_family)) {
			fail("Name len is mismatch: iter=%d, %d %d", i, hdr.msg_namelen, sk_name_len(sk_name));
			return 1;
		}
		if (sk_name_len(sk_name) && memcmp(addr.sun_path, sk_name, sk_name_len(sk_name))) {
			fail("A sender address is mismatch");
			return 1;
		}
	}

	pass();
	return 0;
}
