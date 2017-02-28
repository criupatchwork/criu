#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>

#include "crtools.h"
#include "common/compiler.h"
#include "imgset.h"
#include "rst_info.h"
#include "eventpoll.h"
#include "fdinfo.h"
#include "image.h"
#include "util.h"
#include "log.h"
#include "pstree.h"
#include "kcmp-ids.h"
#include "file-ids.h"

#include "protobuf.h"
#include "images/eventpoll.pb-c.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "epoll: "

struct eventpoll_dump_info {
	EventpollFileEntry		efe;
	struct list_head		list;
	struct list_head		ep_list;
	pid_t				pid;
	int				fd;
};

struct eventpoll_file_info {
	EventpollFileEntry		*efe;
	struct file_desc		d;
};

struct eventpoll_tfd_file_info {
	EventpollTfdEntry		*tdefe;
	struct list_head		list;
};

static LIST_HEAD(eventpoll_tfds);
static LIST_HEAD(eventpoll_fds);

/* Checks if file descriptor @lfd is eventfd */
int is_eventpoll_link(char *link)
{
	return is_anon_link_type(link, "[eventpoll]");
}

static void pr_info_eventpoll_tfd(char *action, EventpollTfdEntry *e)
{
	pr_info("%seventpoll-tfd: id %#08x tfd %#08x events %#08x data %#016"PRIx64"\n",
		action, e->id, e->tfd, e->events, e->data);
}

static void pr_info_eventpoll(char *action, EventpollFileEntry *e)
{
	pr_info("%seventpoll: id %#08x flags %#04x\n", action, e->id, e->flags);
}

struct eventpoll_list {
	struct list_head list;
	int n;
};

static int collect_eventpoll_entry(union fdinfo_entries *e, void *arg)
{
	struct eventpoll_list *ep_list = (struct eventpoll_list *) arg;
	EventpollTfdEntry *efd = &e->epl.e;

	pr_info_eventpoll_tfd("Collecting: ", efd);

	list_add_tail(&e->epl.node, &ep_list->list);
	ep_list->n++;

	return 0;
}

static int collect_one_eventpoll(int lfd, u32 id, const struct fd_parms *p)
{
	struct eventpoll_dump_info *dinfo;
	struct eventpoll_list ep_list = {LIST_HEAD_INIT(ep_list.list), 0};
	union fdinfo_entries *te, *tmp;
	int i;

	dinfo = xmalloc(sizeof(*dinfo) + sizeof(*dinfo->efe.fown));
	if (!dinfo)
		return -ENOMEM;
	INIT_LIST_HEAD(&dinfo->ep_list);

	eventpoll_file_entry__init(&dinfo->efe);

	dinfo->efe.fown = (void *)dinfo + sizeof(*dinfo);
	fown_entry__init(dinfo->efe.fown);

	dinfo->pid			= p->pid;
	dinfo->efe.id			= id;
	dinfo->efe.flags		= p->flags;
	dinfo->efe.fown->uid		= p->fown.uid;
	dinfo->efe.fown->euid		= p->fown.euid;
	dinfo->efe.fown->signum		= p->fown.signum;
	dinfo->efe.fown->pid_type	= p->fown.pid_type;
	dinfo->efe.fown->pid		= p->fown.pid;
	dinfo->fd			= p->fd;

	if (parse_fdinfo(lfd, FD_TYPES__EVENTPOLL, collect_eventpoll_entry, &ep_list)) {
		xfree(dinfo);
		return -1;
	}

	dinfo->efe.tfd = xmalloc(sizeof(struct EventpollTfdEntry *) * ep_list.n);
	if (!dinfo->efe.tfd) {
		xfree(dinfo);
		return -ENOMEM;
	}

	i = 0;
	list_for_each_entry_safe(te, tmp, &ep_list.list, epl.node) {
		list_move_tail(&te->epl.node, &dinfo->ep_list);
		dinfo->efe.tfd[i++] = &te->epl.e;
	}
	dinfo->efe.n_tfd = ep_list.n;

	pr_info_eventpoll("Collecting ", &dinfo->efe);
	list_add(&dinfo->list, &eventpoll_fds);

	return 0;
}

const struct fdtype_ops eventpoll_dump_ops = {
	.type		= FD_TYPES__EVENTPOLL,
	.dump		= collect_one_eventpoll,
};

int dump_eventpoll(void)
{
	struct eventpoll_dump_info *dinfo, *dinfo_tmp;
	union fdinfo_entries *te, *te_tmp;
	int ret = -1, prev_tfd;
	struct kid_elem *kid;

	list_for_each_entry(dinfo, &eventpoll_fds, list) {
		unsigned long nr_valid = 0;
		kcmp_epoll_slot_t slot = {
			.efd	= dinfo->fd,
			.toff	= 0,
		};

		prev_tfd = -1;
		list_for_each_entry(te, &dinfo->ep_list, epl.node) {
			slot.tfd = te->epl.e.tfd;
			if (prev_tfd == slot.tfd)
				slot.toff++;
			prev_tfd = slot.tfd;

			if (te->epl.use_kcmp) {
				kid = fd_kid_epoll_lookup(dinfo->pid,
							  te->epl.gen_id,
							  &slot);
				if (!kid || kid->pid != dinfo->pid ||
				    kid->idx != te->epl.e.tfd) {
					pr_warn("Target %d not found for pid %d "
						"(or pid mismatsh %d), ignoring\n",
						te->epl.e.tfd, dinfo->pid,
						kid ? kid->pid : -1);
					te->epl.valid = 0;
				} else {
					pr_debug("Target %d for pid %d matched fd %d\n",
						 te->epl.e.tfd, dinfo->pid, kid->idx);
					nr_valid++;
				}
			} else {
				char path[PATH_MAX];

				snprintf(path, sizeof(path), "/proc/%d/fd/%d",
					 dinfo->pid, slot.tfd);
				if (access(path, F_OK)) {
					pr_warn("Target %d not found for pid %d, ignoring\n",
						te->epl.e.tfd, dinfo->pid);
					te->epl.valid = 0;
				} else {
					pr_debug("Target %d for pid %d is accessible\n",
						 te->epl.e.tfd, dinfo->pid);
					nr_valid++;
				}
			}
		}

		if (nr_valid != dinfo->efe.n_tfd) {
			size_t i = 0;

			EventpollTfdEntry **tfd = xmalloc(sizeof(struct EventpollTfdEntry *) * nr_valid);
			if (!tfd)
				goto out;

			list_for_each_entry(te, &dinfo->ep_list, epl.node) {
				if (te->epl.valid)
					tfd[i++] = &te->epl.e;
			}

			xfree(dinfo->efe.tfd);
			dinfo->efe.tfd = tfd;
			dinfo->efe.n_tfd = nr_valid;
		}

		pr_info_eventpoll("Dumping ", &dinfo->efe);
		if (pb_write_one(img_from_set(glob_imgset, CR_FD_EVENTPOLL_FILE),
				 &dinfo->efe, PB_EVENTPOLL_FILE))
			goto out;
	}

	ret = 0;

out:
	/* Free everything */
	list_for_each_entry_safe(dinfo, dinfo_tmp, &eventpoll_fds, list) {
		list_for_each_entry_safe(te, te_tmp, &dinfo->ep_list, epl.node)
			free_event_poll_entry(te);
		xfree(dinfo->efe.tfd);
		xfree(dinfo);
	}

	return ret;
}

static int eventpoll_post_open(struct file_desc *d, int fd);

static int eventpoll_open(struct file_desc *d, int *new_fd)
{
	struct fdinfo_list_entry *fle = file_master(d);
	struct eventpoll_file_info *info;
	int tmp;

	info = container_of(d, struct eventpoll_file_info, d);

	if (fle->stage >= FLE_OPEN)
		return eventpoll_post_open(d, fle->fe->fd);

	pr_info_eventpoll("Restore ", info->efe);

	tmp = epoll_create(1);
	if (tmp < 0) {
		pr_perror("Can't create epoll %#08x",
			  info->efe->id);
		return -1;
	}

	if (rst_file_params(tmp, info->efe->fown, info->efe->flags)) {
		pr_perror("Can't restore file params on epoll %#08x",
			  info->efe->id);
		goto err_close;
	}

	*new_fd = tmp;
	return 1;
err_close:
	close(tmp);
	return -1;
}

static int epoll_not_ready_tfd(EventpollTfdEntry *tdefe)
{
	struct fdinfo_list_entry *fle;

	list_for_each_entry(fle, &rsti(current)->fds, ps_list) {
		if (tdefe->tfd != fle->fe->fd)
			continue;

		if (fle->desc->ops->type == FD_TYPES__EVENTPOLL)
			return (fle->stage < FLE_OPEN);
		else
			return (fle->stage != FLE_RESTORED);
	}

	/*
	 * If tgt fle is not on the fds list, it's already
	 * restored (see open_fdinfos), so we're ready.
	 */
	return 0;
}

static int eventpoll_retore_tfd(int fd, int id, EventpollTfdEntry *tdefe)
{
	struct epoll_event event;

	pr_info_eventpoll_tfd("Restore ", tdefe);

	event.events	= tdefe->events;
	event.data.u64	= tdefe->data;
	if (epoll_ctl(fd, EPOLL_CTL_ADD, tdefe->tfd, &event)) {
		pr_perror("Can't add event on %#08x", id);
		return -1;
	}

	return 0;
}

static int eventpoll_post_open(struct file_desc *d, int fd)
{
	struct eventpoll_tfd_file_info *td_info;
	struct eventpoll_file_info *info;
	int i;

	info = container_of(d, struct eventpoll_file_info, d);

	for (i = 0; i < info->efe->n_tfd; i++) {
		if (epoll_not_ready_tfd(info->efe->tfd[i]))
			return 1;
	}
	for (i = 0; i < info->efe->n_tfd; i++) {
		if (eventpoll_retore_tfd(fd, info->efe->id, info->efe->tfd[i]))
			return -1;
	}

	list_for_each_entry(td_info, &eventpoll_tfds, list) {
		if (epoll_not_ready_tfd(td_info->tdefe))
			return 1;
	}
	list_for_each_entry(td_info, &eventpoll_tfds, list) {
		if (td_info->tdefe->id != info->efe->id)
			continue;

		if (eventpoll_retore_tfd(fd, info->efe->id, td_info->tdefe))
			return -1;

	}

	return 0;
}

static struct file_desc_ops desc_ops = {
	.type = FD_TYPES__EVENTPOLL,
	.open = eventpoll_open,
};

static int collect_one_epoll_tfd(void *o, ProtobufCMessage *msg, struct cr_img *i)
{
	struct eventpoll_tfd_file_info *info = o;

	if (!deprecated_ok("Epoll TFD image"))
		return -1;

	info->tdefe = pb_msg(msg, EventpollTfdEntry);
	list_add(&info->list, &eventpoll_tfds);
	pr_info_eventpoll_tfd("Collected ", info->tdefe);

	return 0;
}

struct collect_image_info epoll_tfd_cinfo = {
	.fd_type = CR_FD_EVENTPOLL_TFD,
	.pb_type = PB_EVENTPOLL_TFD,
	.priv_size = sizeof(struct eventpoll_tfd_file_info),
	.collect = collect_one_epoll_tfd,
};

static int collect_one_epoll(void *o, ProtobufCMessage *msg, struct cr_img *i)
{
	struct eventpoll_file_info *info = o;

	info->efe = pb_msg(msg, EventpollFileEntry);
	pr_info_eventpoll("Collected ", info->efe);
	return file_desc_add(&info->d, info->efe->id, &desc_ops);
}

struct collect_image_info epoll_cinfo = {
	.fd_type = CR_FD_EVENTPOLL_FILE,
	.pb_type = PB_EVENTPOLL_FILE,
	.priv_size = sizeof(struct eventpoll_file_info),
	.collect = collect_one_epoll,
};
