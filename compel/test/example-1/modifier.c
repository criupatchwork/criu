#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

#include <compel/compel.h>

#include "log.h"
#include "common/list.h"
#include "common/page.h"

#include "modifierpie-blob.h"

#define CONFIG_PIEGEN
#define pie_size(__pie_name)	(round_up(sizeof(__pie_name##_blob) + \
			__pie_name ## _nr_gotpcrel * sizeof(long), page_size()))

extern int compel_stop_task(pid_t pid);

#define PARASITE_CMD_MODIFY	PARASITE_USER_CMDS

typedef struct {
	int	*pvar;
	int	val;
} parasite_mod_t;

/* argv[1] -- info path, argv[2] -- new value */
int main(int argc, char *argv[])
{
	struct parasite_blob_desc *pbd;
	struct parasite_ctl *ctl;
	struct infect_ctx *ictx;
	parasite_mod_t *mod;
	char line[128];
	FILE *f;
	int i;

	pid_t donor_pid;
	int *variable;

	if (argc < 2) {
		pr_err("FAIL: Two args required\n");
		exit(1);
	}

	compel_log_init(__print_on_level, 4);

	for (i = 0; i < 10; i++) {
		if (access(argv[1], R_OK)) {
			sleep(3);
			continue;
		}
		sleep(1);
		break;
	}

	if (i >= 10) {
		pr_err("FAIL: Can't access %s\n", argv[1]);
		exit(1);
	}

	f = fopen(argv[1], "r");
	if (!f) {
		pr_perror("FAIL: Can't open %s", argv[1]);
		exit(1);
	}

	if (!fgets(line, sizeof(line), f)) {
		pr_err("FAIL: Can't read data from %s\n", argv[1]);
		exit(1);
	}
	fclose(f);

	if (sscanf(line, "%d %p", &donor_pid, &variable) != 2) {
		pr_err("FAIL: Can't parse data from %s\n", argv[1]);
		exit(1);
	}

	if (compel_stop_task(donor_pid) < 0) {
		pr_err("FAIL: Can't stop task %d\n", donor_pid);
		exit(1);
	}

	ctl = compel_prepare(donor_pid);
	if (!ctl) {
		pr_err("FAIL: Can't prepare compel for %d\n", donor_pid);
		exit(1);
	}

	ictx = compel_infect_ctx(ctl);
	ictx->log_fd = STDOUT_FILENO;

	pbd			= compel_parasite_blob_desc(ctl);
	pbd->mem		= modifier_blob;
	pbd->bsize		= sizeof(modifier_blob);
	pbd->size		= pie_size(modifier);
	pbd->parasite_ip_off	= modifier_blob_offset____export_parasite_head_start;
	pbd->addr_cmd_off	= modifier_blob_offset____export_parasite_cmd;
	pbd->addr_arg_off	= modifier_blob_offset____export_parasite_args;
	pbd->relocs		= modifier_relocs;
	pbd->nr_relocs		= sizeof(modifier_relocs) / sizeof(modifier_relocs[0]);

	if (compel_infect(ctl, 1, 16 << 10) < 0) {
		pr_err("FAIL: Can't infect %d\n", donor_pid);
		if (compel_cure(ctl))
			pr_err("FAIL: Can't cure %d\n", donor_pid);
		exit(1);
	}

	mod = compel_parasite_args(ctl, parasite_mod_t);
	mod->pvar = (int *)(unsigned long)variable;
	mod->val = atoi(argv[2]);

	if (compel_rpc_call_sync(PARASITE_CMD_MODIFY, ctl)) {
		pr_err("FAIL: Parasite cmd %d for %d failer\n",
		       PARASITE_CMD_MODIFY, donor_pid);
		if (compel_cure(ctl))
			pr_err("FAIL: Can't cure %d\n", donor_pid);
		exit(1);
	}

	if (compel_stop_daemon(ctl)) {
		pr_err("FAIL: Can't stop daemon for %d\n", donor_pid);
		if (compel_cure(ctl))
			pr_err("FAIL: Can't cure %d\n", donor_pid);
		exit(1);
	}

	if (compel_cure(ctl)) {
		pr_err("FAIL: Can't cure %d\n", donor_pid);
		exit(1);
	}

	return 0;
}
