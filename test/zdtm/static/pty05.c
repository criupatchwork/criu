#define _XOPEN_SOURCE 500

#include <termios.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mount.h>

#include "zdtmtst.h"

const char *test_doc	= "Test multiple PTYs with different session leaders";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

static int pty_get_index(int fd)
{
	int index;

	if (ioctl(fd, TIOCGPTN, &index)) {
		pr_perror("Can't fetch ptmx index");
		return -1;
	}

	return index;
}

static int open_pty_pair(char *dir, int *fdm, int *fds)
{
	char path[PATH_MAX];
	int index;

	snprintf(path, sizeof(path), "%s/ptmx", dir);
	*fdm = open(path, O_RDWR);
	if (*fdm < 0) {
		pr_perror("Can't open %s", path);
		return -1;
	}

	grantpt(*fdm);
	unlockpt(*fdm);

	index = pty_get_index(*fdm);
	if (index < 0) {
		close(*fdm);
		return -1;
	}

	snprintf(path, sizeof(path), "%s/%d", dir, index);
	*fds = open(path, O_RDWR);
	if (*fds < 0) {
		pr_perror("Can't open %s\n", path);
		close(*fdm);
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	char path[PATH_MAX], *dir1, *dir2;
	int fdm1, fdm2, fds1, fds2;

	test_init(argc, argv);

	if (mkdir(dirname, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) {
		pr_perror("Can't create testing directory %s", dirname);
		exit(1);
	}

	snprintf(path, sizeof(path), "%s/%s", dirname, "lvl1");
	dir1 = strdup(path);

	if (!dir1 || mkdir(path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) {
		pr_perror("Can't create testing directory %s", path);
		exit(1);
	}
	if (mount("devpts", path, "devpts", 0, "newinstance,ptmxmode=0666")) {
		pr_perror("Can't mount testing directory %s", path);
		exit(1);
	}

	snprintf(path, sizeof(path), "%s/%s", dirname, "lvl2");
	dir2 = strdup(path);
	if (!dir2 || mkdir(path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) {
		umount(dir1);
		pr_perror("Can't create testing directory %s", path);
		exit(1);
	}
	if (mount("devpts", path, "devpts", 0, "newinstance,ptmxmode=0666")) {
		umount(dir1);
		pr_perror("Can't mount testing directory %s", path);
		exit(1);
	}

	if (open_pty_pair(dir1, &fdm1, &fds1) ||
	    open_pty_pair(dir2, &fdm2, &fds2)) {
		umount(dir1);
		umount(dir2);
		exit(1);
	}

	test_daemon();
	test_waitsig();

	umount(dir1);
	umount(dir2);

	pass();

	return 0;
}
