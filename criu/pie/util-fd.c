#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mount.h>
#include <stdbool.h>
#include <errno.h>

#include "int.h"
#include "common/compiler.h"
#include "log.h"
#include "string.h"

#ifdef CR_NOGLIBC
# include "uapi/std/syscall.h"
# define __sys(foo)	sys_##foo
#else
# define __sys(foo)	foo
#endif

#include "util-pie.h"
#include "fcntl.h"

#include "common/bug.h"

#include "common/scm-code.c"
