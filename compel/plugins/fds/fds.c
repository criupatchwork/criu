#include <errno.h>

#include "uapi/plugins.h"

#include "uapi/std/syscall.h"
#include "uapi/std/string.h"
#include "uapi/plugin-fds.h"

#include "std-priv.h"
#include "log.h"

#include "common/compiler.h"
#include "common/bug.h"

#define __sys(foo)	sys_##foo
#define __memcpy	std_memcpy

#ifdef SCM_FDSET_HAS_OPTS
#error "Spurious SCM_FDSET_HAS_OPTS"
#endif

#define SCM_FDSET_HAS_OPTS

#include "common/scm.h"
#include "common/scm-code.c"

int fds_send(int *fds, int nr_fds)
{
	return 0; // fds_send_via(std_ctl_sock(), fds, nr_fds);
}

int fds_recv(int *fds, int nr_fds)
{
	return -1; //fds_recv_via(std_ctl_sock(), fds, nr_fds);
}

PLUGIN_REGISTER_DUMMY(fds)
