#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "pstree.h"
#include "util.h"
#include "cr_options.h"
#include "lsm.h"
#include "apparmor.h"

#include "protobuf.h"
#include "images/inventory.pb-c.h"
#include "images/creds.pb-c.h"

#ifdef CONFIG_HAS_SELINUX
#include <selinux/selinux.h>
#endif

static Lsmtype	lsmtype;
static int	(*get_label)(pid_t, char **) = NULL;
static char	*name = NULL;

static int apparmor_get_label(pid_t pid, char **profile_name)
{
	FILE *f;
	char *space;

	f = fopen_proc(pid, "attr/current");
	if (!f)
		return -1;

	if (fscanf(f, "%ms", profile_name) != 1) {
		fclose(f);
		pr_perror("err scanfing");
		return -1;
	}

	fclose(f);

	/*
	 * A profile name can be followed by an enforcement mode, e.g.
	 *	lxc-default-with-nesting (enforced)
	 * but the profile name is just the part before the space.
	 */
	space = strstr(*profile_name, " ");
	if (space)
		*space = 0;

	/*
	 * An "unconfined" value means there is no profile, so we don't need to
	 * worry about trying to restore one.
	 */
	if (strcmp(*profile_name, "unconfined") == 0) {
		free(*profile_name);
		*profile_name = NULL;
	}

	return 0;
}

#ifdef CONFIG_HAS_SELINUX
static int selinux_get_label(pid_t pid, char **output)
{
	security_context_t ctx;
	char *pos, *last;
	int i;

	if (getpidcon_raw(pid, &ctx) < 0) {
		pr_perror("getting selinux profile failed");
		return -1;
	}

	*output = NULL;

	/*
	 * Since SELinux attributes can be finer grained than at the task
	 * level, and we currently don't try to dump any of these other bits,
	 * let's only allow unconfined profiles, which look something like:
	 *
	 *	unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
	 */
	pos = (char*)ctx;
	for (i = 0; i < 3; i++) {
		last = pos;
		pos = strstr(pos, ":");
		if (!pos) {
			pr_err("Invalid selinux context %s\n", (char *)ctx);
			freecon(ctx);
			return -1;
		}

		*pos = 0;
		if (!strstartswith(last, "unconfined_")) {
			pr_err("Non unconfined selinux contexts not supported %s\n", last);
			freecon(ctx);
			return -1;
		}

		pos++;
	}
	freecon(ctx);

	return 0;
}
#endif

void kerndat_lsm(void)
{
	/* On restore, if someone passes --lsm-profile, we might end up doing
	 * detection twice, once during flag parsing and once for
	 * kerndat_init_rst(). Let's detect when we've already done detection
	 * and not do it again.
	 */
	if (name)
		return;

	if (access(AA_SECURITYFS_PATH, F_OK) == 0) {
		get_label = apparmor_get_label;
		lsmtype = LSMTYPE__APPARMOR;
		name = "apparmor";
		ns_dumping_enabled = check_aa_ns_dumping();
		return;
	}

#ifdef CONFIG_HAS_SELINUX
	/*
	 * This seems to be the canonical place to mount this fs if it is
	 * enabled, although we may (?) want to check /selinux for posterity as
	 * well.
	 */
	if (access("/sys/fs/selinux", F_OK) == 0) {
		get_label = selinux_get_label;
		lsmtype = LSMTYPE__SELINUX;
		name = "selinux";
		return;
	}
#endif

	get_label = NULL;
	lsmtype = LSMTYPE__NO_LSM;
	name = "none";
}

Lsmtype host_lsm_type(void)
{
	return lsmtype;
}

static int collect_lsm_profile(pid_t pid, char **profile)
{
	*profile = NULL;

	if (lsmtype == LSMTYPE__NO_LSM)
		return 0;

	if (get_label(pid, profile) < 0)
		return -1;

	if (lsmtype == LSMTYPE__APPARMOR && collect_aa_namespace(*profile) < 0) {
		pr_err("failed to collect AA namespace\n");
		return -1;
	}

	if (*profile)
		pr_info("%d has lsm profile %s\n", pid, *profile);

	return 0;
}

int collect_and_suspend_lsm(void)
{
	struct pstree_item *item;

	for_each_pstree_item(item) {
		int i;

		dmpi(item)->thread_lsms = xmalloc(item->nr_threads * sizeof(char));
		if (!dmpi(item)->thread_lsms)
			return -1;

		for (i = 0; i < item->nr_threads; i++) {
			if (collect_lsm_profile(item->threads[i].real, &dmpi(item)->thread_lsms[i]) < 0)
				return -1;
		}
	}

	/* now, suspend the LSM */
	switch(lsmtype) {
	default:
		pr_warn("don't know how to suspend LSM %d\n", lsmtype);
	}

	return 0;
}

int unsuspend_lsm(void)
{

	return 0;
}

// in inventory.c
extern Lsmtype image_lsm;

int render_lsm_profile(char *profile, char **val)
{
	*val = NULL;

	if (image_lsm != lsmtype) {
		pr_err("image lsm doesn't match current kernel's lsm\n");
		return -1;
	}

	/* nothing to do */
	if (!profile)
		return 0;

	switch (lsmtype) {
	case LSMTYPE__APPARMOR:
		return render_aa_profile(val, profile);
	case LSMTYPE__SELINUX:
		if (opts.lsm_supplied) {
			if (!opts.lsm_profile)
				return 0;

			profile = opts.lsm_profile;
		}

		if (asprintf(val, "%s", profile) < 0) {
			*val = NULL;
			return -1;
		}
		break;
	default:
		pr_err("can't render profile %s for lsmtype %d\n", profile, LSMTYPE__NO_LSM);
		return -1;
	}

	return 0;
}

int parse_lsm_arg(char *arg)
{
	char *aux;

	kerndat_lsm();

	aux = strchr(arg, ':');
	if (aux == NULL) {
		pr_err("invalid argument %s for --lsm-profile", arg);
		return -1;
	}

	*aux = '\0';
	aux++;

	if (strcmp(arg, "apparmor") == 0) {
		if (lsmtype != LSMTYPE__APPARMOR) {
			pr_err("apparmor LSM specified but apparmor not supported by kernel\n");
			return -1;
		}

		opts.lsm_profile = aux;
	} else if (strcmp(arg, "selinux") == 0) {
		if (lsmtype != LSMTYPE__SELINUX) {
			pr_err("selinux LSM specified but selinux not supported by kernel\n");
			return -1;
		}

		opts.lsm_profile = aux;
	} else if (strcmp(arg, "none") == 0) {
		opts.lsm_profile = NULL;
	} else {
		pr_err("unknown lsm %s\n", arg);
		return -1;
	}

	opts.lsm_supplied = true;

	return 0;
}
