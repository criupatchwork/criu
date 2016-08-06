#include <sched.h>
#include <unistd.h>

#include "criu-log.h"
#include "crtools.h"
#include "pstree.h"
#include "files.h"
#include "files-reg.h"
#include "mount.h"
#include "cr_options.h"
#include "namespaces.h"
#include "util.h"

static int gc_validate_opts(void)
{
	/*
	 * To work properly gc should be done in the same environment as
	 * dump was done in. So prohibit environment changes on gc.
	 */
	if (opts.unshare_flags)  {
		pr_err("Unshare options are not compatible with gc command\n");
		return -1;
	}

	return 0;
}

static int root_mntns = -1;

static int gc_setup_mntns(void)
{
	if (mntns_maybe_create_roots() < 0)
		return -1;

	if (read_mnt_ns_img() < 0)
		return -1;

	if (root_ns_mask & CLONE_NEWNS) {
		/* prepare_mnt_ns() expects that root mnt ns is already created */
		if (unshare(CLONE_NEWNS)) {
			pr_perror("Couldn't create root mount namespace\n");
			return -1;
		}

		root_mntns = open_proc(PROC_SELF, "ns/mnt");
		if (root_mntns < 0)
			return -1;
	}

	if (prepare_mnt_ns() < 0)
		return -1;

	if (prepare_remaps() < 0)
		return -1;

	return 0;
}

static int gc_cleanup_mntns(void)
{
	int ret = depopulate_roots_yard(root_mntns, false);

	if ((root_mntns != -1) && close(root_mntns)) {
		pr_perror("Couldn't close root mntns fd");
		ret = -1;
	}

	return ret;
}

static int gc_show(void)
{
	show_link_remaps();

	return 0;
}

static int gc_do(void)
{
	if (gc_link_remaps() < 0)
		return -1;

	return 0;
}

int cr_gc(void)
{
	int ret = 0;

	if (gc_validate_opts() < 0) {
		ret = -1;
		goto exit;
	}

	if (check_img_inventory() < 0) {
		ret = -1;
		goto exit;
	}

	if (prepare_task_entries() < 0) {
		ret = -1;
		goto exit;
	}

	if (prepare_pstree() < 0) {
		ret = -1;
		goto exit;
	}

	if (prepare_shared_fdinfo() < 0) {
		ret = -1;
		goto exit;
	}

	if (collect_remaps_and_regfiles()) {
		ret = -1;
		goto exit;
	}

	if (gc_setup_mntns()) {
		ret = -1;
		goto exit;
	}

	if (opts.show)
		ret = gc_show();
	else
		ret = gc_do();

exit:
	if (gc_cleanup_mntns())
		ret = -1;

	return ret;
}
