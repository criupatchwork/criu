#ifndef __CR_LSM_H__
#define __CR_LSM_H__

#include "images/inventory.pb-c.h"
#include "images/creds.pb-c.h"

#define AA_SECURITYFS_PATH "/sys/kernel/security/apparmor"

/*
 * Get the Lsmtype for the current host.
 */
extern Lsmtype host_lsm_type(void);

/*
 * Initialize the Lsmtype for the current host
 */
extern void kerndat_lsm(void);

/*
 * Read the LSM profile for the pstree item
 */
extern int collect_lsm_profile(pid_t, CredsEntry *);

/*
 * Render the profile name in the way that the LSM wants it written to
 * /proc/<pid>/attr/current, according to whatever is in the images and
 * specified by --lsm-profile.
 */
int render_lsm_profile(char *profile, char **val);

extern int parse_lsm_arg(char *arg);
#endif /* __CR_LSM_H__ */
