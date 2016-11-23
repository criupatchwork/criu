#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include <sys/types.h>

static int variable = 1;

/* argv[1] -- info path, argv[2] -- new value */
int main(int argc, char *argv[])
{
	int expected = 0, nr_waits = 20;
	char info[128];
	int i, fd, size;

	if (argc < 3) {
		printf("FAIL: Not enough params passed\n");
		exit(1);
	}

	expected = atoi(argv[2]);

	printf("INFO: donor %d variable %p value %d => %d\n",
	       getpid(), &variable, variable, expected);

	fd = open(argv[1], O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		printf("FAIL: Can't open %s: %m\n", argv[1]);
		exit(1);
	}

	snprintf(info, sizeof(info), "%d %p\n", getpid(), &variable);
	size = strlen(info);
	if (write(fd, info, size) != size) {
		printf("FAIL: Incomplete write of data\n");
		exit(1);
	}
	close(fd);

	for (i = 0; i < nr_waits; i++) {
		printf("INFO: %d: %s (got %d expected %d nr %d/%d)\n",
		       getpid(),
		       expected == variable ? "Match" : "Mismatch",
		       variable, expected, i, nr_waits);
		if (expected == variable) {
			printf("PASS: %d\n", getpid());
			exit(0);
		}
		sleep(1);
	}

	printf("FAIL: %d\n", getpid());
	return 1;
}
