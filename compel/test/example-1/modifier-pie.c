#include <errno.h>

#include <compel/plugins/std/syscall.h>
#include <compel/plugins/std/string.h>
#include <compel/plugins/std/log.h>

#include <compel/infect-rpc.h>

/*
 * These are stubs for std compel plugin.
 */
int compel_main(void *arg_p, unsigned int arg_s) { return 0; }
int parasite_trap_cmd(int cmd, void *args) { return 0; }
void parasite_cleanup(void) { }

#define PARASITE_CMD_MODIFY	PARASITE_USER_CMDS

typedef struct {
	int	*pvar;
	int	val;
} parasite_mod_t;

int parasite_daemon_cmd(int cmd, void *args)
{
	std_printf("INFO: modifier-pie: parasite_daemon_cmd %d\n", cmd);

	if (cmd == PARASITE_CMD_MODIFY) {
		parasite_mod_t *p = args;
		*p->pvar = p->val;
		return 0;
	}

	return -EINVAL;
}
