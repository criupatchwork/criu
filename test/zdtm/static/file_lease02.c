#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <limits.h>

#include "zdtmtst.h"

#define FD_COUNT 3

const char *test_doc = "Check that breaking leases are restored";
const char *test_author = "Pavel Begunkov <asml.silence@gmail.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

char filename1[PATH_MAX];
char filename2[PATH_MAX];
char filename3[PATH_MAX];

static int check_lease_type(int fd, int expected_type)
{
	int lease_type = fcntl(fd, F_GETLEASE);

	if (lease_type != expected_type) {
		if (lease_type < 0)
			pr_perror("Can't acquire lease type\n");
		else
			pr_err("Mismatched lease type: %i\n", lease_type);
		return -1;
	}
	return 0;
}

int prepare_file(char* file, int file_type, int break_type)
{
	int fd, fd_break;
	int lease_type = (file_type == O_RDONLY) ? F_RDLCK : F_WRLCK;

	fd = open(file, file_type | O_CREAT, 0666);
	if (fd < 0) {
		pr_perror("Can't open file (type %i)\n", file_type);
		return fd;
	}

	if (fcntl(fd, F_SETLEASE, lease_type) < 0) {
		close(fd);
		pr_perror("Can't set exclusive lease\n");
		return -1;
	}

	fd_break = open(file, break_type | O_NONBLOCK);
	if (fd_break >= 0) {
		close(fd);
		close(fd_break);
		pr_err("Conflicting lease not found\n");
		return -1;
	} else if (errno != EWOULDBLOCK) {
		close(fd);
		pr_perror("Can't break lease\n");
		return -1;
	}
	return fd;
}

void close_files(int fds[FD_COUNT])
{
	for (int i = 0; i < FD_COUNT; ++i)
		if (fds[i] >= 0)
			close(fds[i]);
	unlink(filename1);
	unlink(filename2);
	unlink(filename3);
}

int main(int argc, char **argv)
{
	int fds[FD_COUNT];
	int ret = -1;

	test_init(argc, argv);

	snprintf(filename1, sizeof(filename1), "%s.0", filename);
	snprintf(filename2, sizeof(filename2), "%s.1", filename);
	snprintf(filename3, sizeof(filename3), "%s.2", filename);

	if (signal(SIGIO, SIG_IGN) == SIG_ERR) {
		pr_err("Can't silent SIGIO\n");
		return -1;
	}

	fds[0] = prepare_file(filename1, O_RDONLY, O_WRONLY);
	fds[1] = prepare_file(filename2, O_WRONLY, O_RDONLY);
	fds[2] = prepare_file(filename3, O_WRONLY, O_WRONLY);
	if (fds[0] < 0 || fds[1] < 0 || fds[2] < 0)
		goto done;

	test_daemon();
	test_waitsig();

	ret = 0;
	if (check_lease_type(fds[0], F_UNLCK) ||
		check_lease_type(fds[1], F_RDLCK) ||
		check_lease_type(fds[2], F_UNLCK))
		fail("Lease type doesn't match\n");
	else
		pass();

done:
	close_files(fds);
	return ret;
}

