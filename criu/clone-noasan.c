#include <sched.h>
#include "common/compiler.h"

/*
 * ASan doesn't play nicely with clone if we use current stack for
 * child task. ASan puts local variables on the fake stack
 * to catch use-after-return bug:
 *         https://github.com/google/sanitizers/wiki/AddressSanitizerUseAfterReturn#algorithm
 *
 * So it's become easy to overflow this fake stack frame in cloned child.
 * We need a real stack for clone().
 *
 * To workaround this we add clone_noasan() not-instrumented wrapper for
 * clone(). Unfortunately we can't use __attrbute__((no_sanitize_addresss))
 * for this because of bug in GCC > 6:
 *         https://gcc.gnu.org/bugzilla/show_bug.cgi?id=69863
 *
 * So the only way is to put this wrapper in separate non-instrumented file
 */
int clone_noasan(int (*fn)(void *), int flags, void *arg)
{
	int ret;
	/*
	 * Reserve some space for clone() to locate arguments
	 * and retcode in this place. stack_ptr is set out of the current used
	 * stack to be able to use CLONE_VFORK | CLONE_VM.
	 */
	void *stack_ptr = (void *) round_down(((unsigned long) &ret) - 256, 16);

	ret = clone(fn, stack_ptr, flags, arg);
	return ret;
}

