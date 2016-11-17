#include <errno.h>

#include "uapi/plugins.h"

#include "uapi/std/syscall.h"
#include "uapi/std/string.h"
#include "uapi/plugin-fds.h"

#include "uapi/std/log.h"
#include "std-priv.h"

/*
 * FIXME pr_X helpers should go into some
 * common/pr-base.h header.
 */
#define pr_err(fmt, ...)

#include "common/compiler.h"
#include "common/bug.h"

#define __sys(foo)	sys_##foo
#define __memcpy	std_memcpy

#include "common/scm-code.c"

PLUGIN_REGISTER_DUMMY(fds)
