#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sched.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/mount.h>
#include <dirent.h>

#include "zdtmtst.h"

const char *test_doc	= "Check ghost files on a read-only mount";
const char *test_author	= "Andrew Vagin <avagin@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);


int main(int argc, char **argv)
{
	task_waiter_t lock;
	pid_t pid = -1;
	int status = 1;

	test_init(argc, argv);
	task_waiter_init(&lock);

	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		return 1;
	}

	if (pid == 0) {
		char dname[PATH_MAX], dname_ro[PATH_MAX];
		int fd;
		DIR *d;
		struct dirent *de;

		if (unshare(CLONE_NEWNS)) {
			pr_perror("unshare");
			return 1;
		}
		if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL)) {
			pr_perror("mount");
			return 1;
		}

		if (mkdir(dirname, 0600) < 0) {
			pr_perror("mkdir");
			return 1;
		}

		if (mount(dirname, dirname, NULL, MS_BIND, NULL)) {
			pr_perror("mount");
			return 1;
		}

		snprintf(dname, PATH_MAX, "%s/tmpfs", dirname);
		snprintf(dname_ro, PATH_MAX, "%s/ro", dirname);

		mkdir(dname_ro, 0755);

		if (mount(dirname, dname_ro, NULL, MS_BIND, NULL)) {
			pr_perror("mount");
			return 1;
		}
		if (mount(NULL, dname_ro, NULL, MS_BIND | MS_RDONLY | MS_REMOUNT, NULL)) {
			pr_perror("mount");
			return 1;
		}

		if (chdir(dirname))
			return 1;

		fd = open("test.ghost", O_CREAT | O_WRONLY, 0600);
		if (fd < 0) {
			pr_perror("open");
			return 1;
		}
		close(fd);

		fd = open("ro/test.ghost", O_RDONLY, 0600);
		if (fd < 0) {
			pr_perror("open");
			return 1;
		}

		if (unlink("test.ghost")) {
			pr_perror("unlink");
			return 1;
		}

		task_waiter_complete(&lock, 1);
		test_waitsig();

		if (close(fd)) {
			pr_perror("close");
			return 1;
		}
		d = opendir(".");
		if (d == NULL) {
			pr_perror("opendir");
			return 1;
		}
		while ((de = readdir(d)) != NULL) {
			if (!strcmp(de->d_name, "."))
				continue;
			if (!strcmp(de->d_name, ".."))
				continue;
			pr_err("%s\n", de->d_name);
		}
		closedir(d);

		return 0;
	}

	task_waiter_wait4(&lock, 1);
	test_daemon();
	test_waitsig();


	kill(pid, SIGTERM);
	wait(&status);
	if (status) {
		fail("Test died");
		return 1;
	}
	pass();

	return 0;
}
