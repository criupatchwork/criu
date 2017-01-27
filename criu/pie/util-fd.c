#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mount.h>
#include <stdbool.h>
#include <errno.h>

#include "int.h"
#include "types.h"
#include "common/compiler.h"
#include "log.h"
#include "string.h"

#ifdef CR_NOGLIBC
# include <compel/plugins/std/syscall.h>
# define __sys(foo)	sys_##foo
#else
# define __sys(foo)	foo
#endif

# include <compel/plugins/std/string.h>
#define __memcpy std_memcpy

#include "util-pie.h"
#include "fcntl.h"

#include "common/bug.h"

#include "common/scm-code.c"
