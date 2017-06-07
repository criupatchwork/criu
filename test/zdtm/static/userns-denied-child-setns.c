#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <sched.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <limits.h>

#include "zdtmtst.h"
#include "lock.h"

const char *test_doc	= "Check that namespaces are correctly inherited";
const char *test_author	= "Kirill Tkhai <ktkhai@virtuozzo.com>";

/*
 *  1)Create a child with CLONE_NEWNET|CLONE_NEWUSER.
 *  2)setns() to its net_ns.
 *  3)Create second child with CLONE_NEWUSER|CLONE_NEWPID
 *    (and it inherits net_ns of first child).
 *  4)Restore original net_ns.
 */

enum {
	FUTEX_INITIALIZED = 0,
	MAPS_SET,
	CHILD_PREPARED,
	POST_RESTORE_CHECK,
	EMERGENCY_ABORT,
};

futex_t *futex;

int write_map(pid_t pid, char *file, char *map)
{
	char path[PATH_MAX];
	int fd, ret;

	sprintf(path, "/proc/%d/%s", pid, file);
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		fail("Can't open");
		return -1;
	}
	ret = write(fd, map, strlen(map));
	if (ret != strlen(map)) {
		fail("Can't write");
		close(fd);
		return -1;
	}
	close(fd);

	return 0;
}

int child_fn(void *arg)
{
	futex_wait_while_lt(futex, MAPS_SET);
	setuid(0);
	setgid(0);
	futex_set_and_wake(futex, CHILD_PREPARED);
	return pause();
}

int main(int argc, char **argv)
{
	int i, net_ns_fd, fd;
	char path[64];
	pid_t pid[2];
	int status;

	test_init(argc, argv);
	futex = mmap(NULL, sizeof(*futex), PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (futex == MAP_FAILED) {
		fail("mmap futex\n");
		return 1;
	}
	futex_init(futex);

	/* save original net namespace fd */
	net_ns_fd = open("/proc/self/ns/net", O_RDONLY);
	if (net_ns_fd < 0) {
		fail("open");
		return 1;
	}

	{
		/* Create first child */
		char stack;
		pid[0] = clone(child_fn, &stack - 256, CLONE_NEWUSER|CLONE_NEWNET, NULL);
		if (pid[0] == -1) {
			fail("clone");
			return 1;
		}
	}

	if (write_map(pid[0], "uid_map", "0 10 1") < 0 ||
	    write_map(pid[0], "gid_map", "0 12 1") < 0) {
		fail("write map");
		goto out_kill;
	}
	futex_set_and_wake(futex, MAPS_SET);
	futex_wait_while_lt(futex, CHILD_PREPARED);

	sprintf(path, "/proc/%d/ns/net", pid[0]);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fail("open");
		goto out_kill;
	}

	if (setns(fd, CLONE_NEWNET)) {
		fail("setns");
		goto out_kill;
	}

	futex_init(futex);
	{
		/* Create second child */
		char stack;
		pid[1] = clone(child_fn, &stack - 256, CLONE_NEWUSER|CLONE_NEWPID, NULL);
		if (pid[1] == -1) {
			fail("clone");
			goto out_kill;
		}
	}

	if (write_map(pid[1], "uid_map", "0 10 1") < 0 ||
	    write_map(pid[1], "gid_map", "0 12 1") < 0) {
		fail("write map");
		goto out_kill2;
	}

	futex_set_and_wake(futex, MAPS_SET);
	futex_wait_while_lt(futex, CHILD_PREPARED);

	if (setns(net_ns_fd, CLONE_NEWNET)) {
		fail("setns");
		goto out_kill2;
	}

	close(fd);
	close(net_ns_fd);

	test_daemon();
	test_waitsig();

	for (i = 0; i < 2; i++) {
		kill(pid[i], SIGKILL);
		wait(&status);
	}

	/* If we restore, test is passed */
	pass();
	return 0;
out_kill2:
	kill(pid[1], SIGKILL);
	wait(&status);
out_kill:
	kill(pid[0], SIGKILL);
	wait(&status);
	return 1;
}
