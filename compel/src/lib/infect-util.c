#include "log.h"
#include "common/bug.h"
#include "common/lock.h"

#define SCM_FDSET_HAS_OPTS
#include "common/scm.h"
#include "uapi/compel/plugins/plugin-fds.h"

#include "infect-rpc.h"
#include "infect-util.h"

int compel_util_send_fd(struct parasite_ctl *ctl, int fd)
{
	int sk;

	sk = compel_rpc_sock(ctl);
	if (send_fd(sk, NULL, 0, fd) < 0) {
		pr_perror("Can't send file descriptor");
		return -1;
	}
	return 0;
}

