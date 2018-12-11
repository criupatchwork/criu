#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>

#include "zdtmtst.h"

const char *test_doc	= "See if we can wait() for a zombified child after migration";
const char *test_author	= "Roman Kagan <rkagan@parallels.com>";

int main(int argc, char ** argv)
{
	int status;
	int pid_pipe[2];
	pid_t pid, pid_c;
	siginfo_t siginfo;

	setenv("ZDTM_PIDNS", "1", 1);
	test_init(argc, argv);

	if (pipe(pid_pipe))
		return 1;

	pid = fork();
	if (pid == 0) {
		setsid();
		pid_c = fork();
		if (pid_c == 0)
			return 0;
		if (write(pid_pipe[1], &pid_c, sizeof(pid_c)) != sizeof(pid_c))
			return 1;
		if (waitid(P_PID, pid_c, &siginfo, WNOWAIT | WEXITED) == -1) {
			pr_perror("Unable to wait %d", pid_c);
			exit(1);
		}
		return 0;
	}
	close(pid_pipe[1]);

	if (read(pid_pipe[0], &pid_c, sizeof(pid_c)) != sizeof(pid_c))
		return 1;

	if (waitid(P_PID, pid, &siginfo, WNOWAIT | WEXITED) == -1) {
		pr_perror("Unable to wait %d", pid);
		exit(1);
	}
	if (waitid(P_PID, pid_c, &siginfo, WNOWAIT | WEXITED) == -1) {
		pr_perror("Unable to wait %d", pid_c);
		exit(1);
	}

	test_daemon();
	test_waitsig();

	if (waitpid(pid, &status, 0) == -1) {
		pr_perror("Unable to wait %d", pid);
		exit(1);
	}
	if (waitpid(pid_c, &status, 0) == -1) {
		pr_perror("Unable to wait %d", pid_c);
		exit(1);
	}

	pass();
	return 0;
}
