#ifndef __CR_FILE_IDS_H__
#define __CR_FILE_IDS_H__

#include <stdint.h>

#include "common/compiler.h"
#include "rbtree.h"
#include "kcmp.h"

#include "images/fdinfo.pb-c.h"

#define FD_PID_INVALID		(-2U)
#define FD_DESC_INVALID		(-3U)

struct fdinfo_entry;
struct stat;
struct kid_elem;
struct fd_parms;

extern int fd_id_generate(pid_t pid, FdinfoEntry *fe, struct fd_parms *p);
extern int fd_id_generate_special(struct fd_parms *p, u32 *id);
extern struct kid_elem *fd_kid_epoll_lookup(pid_t pid, unsigned int genid,
					    kcmp_epoll_slot_t *slot);

/*
 * The gen_id thing is used to optimize the comparison of shared files.
 * If two files have different gen_ids, then they are different for sure.
 * If it matches, we don't know it and have to call sys_kcmp().
 *
 * The kcmp-ids.c engine does this trick, see comments in it for more info.
 */
static inline uint32_t kcmp_fd_make_gen_id(uint32_t st_dev, uint32_t st_ino, uint32_t f_pos)
{
	return st_dev ^ st_ino ^ f_pos;
}

#endif /* __CR_FILE_IDS_H__ */
