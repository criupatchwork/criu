#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "linux/userfaultfd.h"

#include "int.h"
#include "page.h"
#include "criu-log.h"
#include "criu-plugin.h"
#include "pagemap.h"
#include "files-reg.h"
#include "kerndat.h"
#include "mem.h"
#include "uffd.h"
#include "util-pie.h"
#include "protobuf.h"
#include "pstree.h"
#include "crtools.h"
#include "cr_options.h"
#include "xmalloc.h"
#include <compel/plugins/std/syscall-codes.h>
#include "restorer.h"
#include "page-xfer.h"
#include "common/lock.h"
#include "rst-malloc.h"
#include "util.h"

#undef  LOG_PREFIX
#define LOG_PREFIX "lazy-pages: "

#define LAZY_PAGES_SOCK_NAME	"lazy-pages.socket"

static mutex_t *lazy_sock_mutex;

struct lazy_iovec {
	struct list_head l;
	unsigned long base;
	unsigned long len;
};

struct lazy_remap {
	struct list_head l;
	unsigned long from;
	unsigned long to;
	unsigned long len;
};

struct pf_info {
	unsigned long addr;
	struct list_head l;
};

struct lazy_pages_info {
	int pid;

	struct list_head iovs;
	struct list_head pfs;
	struct list_head remaps;

	struct lazy_pages_info *parent;

	struct page_read pr;

	unsigned long total_pages;
	unsigned long copied_pages;

	struct epoll_rfd lpfd;

	struct list_head l;

	void *buf;
};

static LIST_HEAD(lpis);
static LIST_HEAD(pending_lpis);

static int handle_uffd_event(struct epoll_rfd *lpfd);

static struct lazy_pages_info *lpi_init(void)
{
	struct lazy_pages_info *lpi = NULL;

	lpi = xmalloc(sizeof(*lpi));
	if (!lpi)
		return NULL;

	memset(lpi, 0, sizeof(*lpi));
	INIT_LIST_HEAD(&lpi->iovs);
	INIT_LIST_HEAD(&lpi->pfs);
	INIT_LIST_HEAD(&lpi->remaps);
	INIT_LIST_HEAD(&lpi->l);
	lpi->lpfd.revent = handle_uffd_event;

	return lpi;
}

static void lpi_fini(struct lazy_pages_info *lpi)
{
	struct lazy_iovec *p, *n;
	struct lazy_remap *p1, *n1;

	if (!lpi)
		return;
	free(lpi->buf);
	list_for_each_entry_safe(p, n, &lpi->iovs, l)
		xfree(p);
	list_for_each_entry_safe(p1, n1, &lpi->remaps, l)
		xfree(p1);
	if (lpi->lpfd.fd > 0)
		close(lpi->lpfd.fd);
	if (lpi->pr.close)
		lpi->pr.close(&lpi->pr);
	free(lpi);
}

static int prepare_sock_addr(struct sockaddr_un *saddr)
{
	int len;

	memset(saddr, 0, sizeof(struct sockaddr_un));

	saddr->sun_family = AF_UNIX;
	len = snprintf(saddr->sun_path, sizeof(saddr->sun_path),
		       "%s", LAZY_PAGES_SOCK_NAME);
	if (len >= sizeof(saddr->sun_path)) {
		pr_err("Wrong UNIX socket name: %s\n", LAZY_PAGES_SOCK_NAME);
		return -1;
	}

	return 0;
}

static int send_uffd(int sendfd, int pid)
{
	int fd;
	int ret = -1;

	if (sendfd < 0)
		return -1;

	fd = get_service_fd(LAZY_PAGES_SK_OFF);
	if (fd < 0) {
		pr_err("%s: get_service_fd\n", __func__);
		return -1;
	}

	mutex_lock(lazy_sock_mutex);

	/* The "transfer protocol" is first the pid as int and then
	 * the FD for UFFD */
	pr_debug("Sending PID %d\n", pid);
	if (send(fd, &pid, sizeof(pid), 0) < 0) {
		pr_perror("PID sending error");
		goto out;
	}

	/* for a zombie process pid will be negative */
	if (pid < 0) {
		ret = 0;
		goto out;
	}

	if (send_fd(fd, NULL, 0, sendfd) < 0) {
		pr_err("send_fd error\n");
		goto out;
	}

	ret = 0;
out:
	mutex_unlock(lazy_sock_mutex);
	close(fd);
	return ret;
}

int lazy_pages_setup_zombie(int pid)
{
	if (!opts.lazy_pages)
		return 0;

	if (send_uffd(0, -pid))
		return -1;

	return 0;
}

/* This function is used by 'criu restore --lazy-pages' */
int setup_uffd(int pid, struct task_restore_args *task_args)
{
	struct uffdio_api uffdio_api;

	if (!opts.lazy_pages) {
		task_args->uffd = -1;
		return 0;
	}

	/*
	 * Open userfaulfd FD which is passed to the restorer blob and
	 * to a second process handling the userfaultfd page faults.
	 */
	task_args->uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (task_args->uffd < 0) {
		pr_perror("Unable to open an userfaultfd descriptor");
		return -1;
	}

	/*
	 * Check if the UFFD_API is the one which is expected
	 */
	uffdio_api.api = UFFD_API;
	uffdio_api.features = 0;
	if (ioctl(task_args->uffd, UFFDIO_API, &uffdio_api)) {
		pr_err("Checking for UFFDIO_API failed.\n");
		goto err;
	}
	if (uffdio_api.api != UFFD_API) {
		pr_err("Result of looking up UFFDIO_API does not match: %Lu\n", uffdio_api.api);
		goto err;
	}

	if (send_uffd(task_args->uffd, pid) < 0)
		goto err;

	return 0;
err:
	close(task_args->uffd);
	return -1;
}

int prepare_lazy_pages_socket(void)
{
	int fd, new_fd;
	int len;
	struct sockaddr_un sun;

	if (!opts.lazy_pages)
		return 0;

	if (prepare_sock_addr(&sun))
		return -1;

	lazy_sock_mutex = shmalloc(sizeof(*lazy_sock_mutex));
	if (!lazy_sock_mutex)
		return -1;

	mutex_init(lazy_sock_mutex);

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return -1;

	new_fd = install_service_fd(LAZY_PAGES_SK_OFF, fd);
	close(fd);
	if (new_fd < 0)
		return -1;

	len = offsetof(struct sockaddr_un, sun_path) + strlen(sun.sun_path);
	if (connect(new_fd, (struct sockaddr *) &sun, len) < 0) {
		pr_perror("connect to %s failed", sun.sun_path);
		close(new_fd);
		return -1;
	}

	return 0;
}

static int server_listen(struct sockaddr_un *saddr)
{
	int fd;
	int len;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return -1;

	unlink(saddr->sun_path);

	len = offsetof(struct sockaddr_un, sun_path) + strlen(saddr->sun_path);

	if (bind(fd, (struct sockaddr *) saddr, len) < 0) {
		goto out;
	}

	if (listen(fd, 10) < 0) {
		goto out;
	}

	return fd;

out:
	close(fd);
	return -1;
}

static MmEntry *init_mm_entry(struct lazy_pages_info *lpi)
{
	struct cr_img *img;
	MmEntry *mm;
	int ret;

	img = open_image(CR_FD_MM, O_RSTR, lpi->pid);
	if (!img)
		return NULL;

	ret = pb_read_one_eof(img, &mm, PB_MM);
	close_image(img);
	if (ret == -1)
		return NULL;
	pr_debug("Found %zd VMAs in image\n", mm->n_vmas);

	return mm;
}

static int copy_lazy_iovecs(struct lazy_pages_info *src,
			    struct lazy_pages_info *dst)
{
	struct lazy_iovec *lazy_iov, *new_iov, *n;
	int max_iov_len = 0;

	list_for_each_entry(lazy_iov, &src->iovs, l) {
		new_iov = xzalloc(sizeof(*new_iov));
		if (!new_iov)
			return -1;

		new_iov->base = lazy_iov->base;
		new_iov->len = lazy_iov->len;

		list_add_tail(&new_iov->l, &dst->iovs);

		if (new_iov->len > max_iov_len)
			max_iov_len = new_iov->len;
	}

	if (posix_memalign(&dst->buf, PAGE_SIZE, max_iov_len))
		goto free_iovs;

	return 0;

free_iovs:
	list_for_each_entry_safe(lazy_iov, n, &dst->iovs, l)
		xfree(lazy_iov);
	return -1;
}

/*
 * Purge range (addr, addr + len) from lazy_iovecs. The range may
 * cover several continuous IOVs.
 */
static int update_lazy_iovecs(struct lazy_pages_info *lpi, unsigned long addr,
			      int len)
{
	struct lazy_iovec *lazy_iov, *n;

	list_for_each_entry_safe(lazy_iov, n, &lpi->iovs, l) {
		unsigned long start = lazy_iov->base;
		unsigned long end = start + lazy_iov->len;

		if (len <= 0)
			break;

		if (addr < start || addr >= end)
			continue;

		/*
		 * The range completely fits into the current IOV.
		 * If addr equals iov_base we just "drop" the
		 * beginning of the IOV. Otherwise, we make the IOV to
		 * end at addr, and add a new IOV start starts at
		 * addr + len.
		 */
		if (addr + len < end) {
			if (addr == start) {
				lazy_iov->base += len;
				lazy_iov->len -= len;
			} else {
				struct lazy_iovec *new_iov;

				lazy_iov->len -= (end - addr);

				new_iov = xzalloc(sizeof(*new_iov));
				if (!new_iov)
					return -1;

				new_iov->base = addr + len;
				new_iov->len = end - (addr + len);

				list_add(&new_iov->l, &lazy_iov->l);
			}
			break;
		}

		/*
		 * The range spawns beyond the end of the current IOV.
		 * If addr equals iov_base we just "drop" the entire
		 * IOV.  Otherwise, we cut the beginning of the IOV
		 * and continue to the next one with the updated range
		 */
		if (addr == start) {
			list_del(&lazy_iov->l);
			xfree(lazy_iov);
		} else {
			lazy_iov->len -= (end - addr);
		}

		len -= (end - addr);
		addr = end;
	}

	return 0;
}

/*
 * Create a list of IOVs that can be handled using userfaultfd. The
 * IOVs generally correspond to lazy pagemap entries, except the cases
 * when a single pagemap entry covers several VMAs. In those cases
 * IOVs are split at VMA boundaries because UFFDIO_COPY may be done
 * only inside a single VMA.
 * We assume here that pagemaps and VMAs are sorted.
 */
static int collect_lazy_iovecs(struct lazy_pages_info *lpi)
{
	struct page_read *pr = &lpi->pr;
	struct lazy_iovec *lazy_iov, *n;
	MmEntry *mm;
	int nr_pages = 0, n_vma = 0, max_iov_len = 0;
	int ret = -1;
	unsigned long start, end, len;

	mm = init_mm_entry(lpi);
	if (!mm)
		return -1;

	while (pr->advance(pr)) {
		if (!pagemap_lazy(pr->pe))
			continue;

		start = pr->pe->vaddr;
		end = start + pr->pe->nr_pages * page_size();
		nr_pages += pr->pe->nr_pages;

		for (; n_vma < mm->n_vmas; n_vma++) {
			VmaEntry *vma = mm->vmas[n_vma];

			if (start >= vma->end)
				continue;

			lazy_iov = xzalloc(sizeof(*lazy_iov));
			if (!lazy_iov)
				goto free_iovs;

			len = min_t(uint64_t, end, vma->end) - start;
			lazy_iov->base = start;
			lazy_iov->len = len;
			list_add_tail(&lazy_iov->l, &lpi->iovs);

			if (len > max_iov_len)
				max_iov_len = len;

			if (end <= vma->end)
				break;

			start = vma->end;
		}
	}

	if (posix_memalign(&lpi->buf, PAGE_SIZE, max_iov_len))
		goto free_iovs;

	ret = nr_pages;
	goto free_mm;

free_iovs:
	list_for_each_entry_safe(lazy_iov, n, &lpi->iovs, l)
		xfree(lazy_iov);
free_mm:
	mm_entry__free_unpacked(mm, NULL);

	return ret;
}

static int uffd_io_complete(struct page_read *pr, unsigned long vaddr, int nr);

static int ud_open(int client, struct lazy_pages_info **_lpi)
{
	struct lazy_pages_info *lpi;
	int ret = -1;
	int pr_flags = PR_TASK;

	lpi = lpi_init();
	if (!lpi)
		goto out;

	/* The "transfer protocol" is first the pid as int and then
	 * the FD for UFFD */
	ret = recv(client, &lpi->pid, sizeof(lpi->pid), 0);
	if (ret != sizeof(lpi->pid)) {
		if (ret < 0)
			pr_perror("PID recv error");
		else
			pr_err("PID recv: short read\n");
		goto out;
	}

	if (lpi->pid < 0) {
		pr_debug("Zombie PID: %d\n", lpi->pid);
		lpi_fini(lpi);
		return 0;
	}

	lpi->lpfd.fd = recv_fd(client);
	if (lpi->lpfd.fd < 0) {
		pr_err("recv_fd error");
		goto out;
	}
	pr_debug("Received PID: %d, uffd: %d\n", lpi->pid, lpi->lpfd.fd);

	if (opts.use_page_server)
		pr_flags |= PR_REMOTE;
	ret = open_page_read(lpi->pid, &lpi->pr, pr_flags);
	if (ret <= 0) {
		ret = -1;
		goto out;
	}

	lpi->pr.io_complete = uffd_io_complete;

	/*
	 * Find the memory pages belonging to the restored process
	 * so that it is trackable when all pages have been transferred.
	 */
	ret = collect_lazy_iovecs(lpi);
	if (ret < 0)
		goto out;
	lpi->total_pages = ret;

	pr_debug("Found %ld pages to be handled by UFFD\n", lpi->total_pages);

	list_add_tail(&lpi->l, &lpis);
	*_lpi = lpi;

	return 0;

out:
	lpi_fini(lpi);
	return -1;
}

static int uffd_copy(struct lazy_pages_info *lpi, __u64 address, int nr_pages)
{
	struct uffdio_copy uffdio_copy;
	struct lazy_remap *r;
	unsigned long len = nr_pages * page_size();
	int rc;

	list_for_each_entry(r, &lpi->remaps, l) {
		if (address >= r->from && address < r->from + r->len) {
			address += (r->to - r->from);
			break;
		}
	}

	uffdio_copy.dst = address;
	uffdio_copy.src = (unsigned long)lpi->buf;
	uffdio_copy.len = len;
	uffdio_copy.mode = 0;
	uffdio_copy.copy = 0;

	pr_debug("%d-%d: uffd_copy: 0x%llx/%ld\n", lpi->pid, lpi->lpfd.fd,
		 uffdio_copy.dst, len);
	rc = ioctl(lpi->lpfd.fd, UFFDIO_COPY, &uffdio_copy);
	if (rc) {
		/* real retval in ufdio_copy.copy */
		if (uffdio_copy.copy != -EEXIST) {
			pr_err("%d-%d: UFFDIO_COPY failed: rc:%d copy:%Ld\n",
			       lpi->pid, lpi->lpfd.fd, rc, uffdio_copy.copy);
			return -1;
		} else {
			pr_debug("%d-%d: pages already present at %llx\n",
				 lpi->pid, lpi->lpfd.fd, address);
		}
	} else if (uffdio_copy.copy != len) {
		pr_err("UFFDIO_COPY unexpected size %Ld\n", uffdio_copy.copy);
		return -1;
	}

	lpi->copied_pages += nr_pages;

	return 0;
}

static int complete_page_fault(struct lazy_pages_info *lpi, unsigned long vaddr, int nr)
{
	struct pf_info *pf;

	if (uffd_copy(lpi, vaddr, nr))
		return -1;

	list_for_each_entry(pf, &lpi->pfs, l) {
		if (pf->addr == vaddr) {
			list_del(&pf->l);
			xfree(pf);
			break;
		}
	}

	return update_lazy_iovecs(lpi, vaddr, nr * PAGE_SIZE);
}

static int uffd_io_complete(struct page_read *pr, unsigned long vaddr, int nr)
{
	struct lazy_pages_info *lpi;

	lpi = container_of(pr, struct lazy_pages_info, pr);
	return complete_page_fault(lpi, vaddr, nr);
}

static int uffd_zero(struct lazy_pages_info *lpi, __u64 address, int nr_pages)
{
	struct uffdio_zeropage uffdio_zeropage;
	unsigned long len = page_size() * nr_pages;
	int rc;

	uffdio_zeropage.range.start = address;
	uffdio_zeropage.range.len = len;
	uffdio_zeropage.mode = 0;

	pr_debug("%d-%d: zero page at 0x%llx\n", lpi->pid, lpi->lpfd.fd, address);
	rc = ioctl(lpi->lpfd.fd, UFFDIO_ZEROPAGE, &uffdio_zeropage);
	if (rc) {
		pr_err("UFFDIO_ZEROPAGE error %d\n", rc);
		return -1;
	}

	return 0;
}

/*
 * Seek for the requested address in the pagemap. If it is found, the
 * subsequent call to pr->page_read will bring us the data. If the
 * address is not found in the pagemap, but no error occured, the
 * address should be mapped to zero pfn.
 *
 * Returns 0 for zero pages, 1 for "real" pages and negative value on
 * error
 */
static int uffd_seek_or_zero_pages(struct lazy_pages_info *lpi, __u64 address,
				   int nr)
{
	int ret;

	lpi->pr.reset(&lpi->pr);

	ret = lpi->pr.seek_pagemap(&lpi->pr, address);
	if (!ret)
		return uffd_zero(lpi, address, nr);

	lpi->pr.skip_pages(&lpi->pr, address - lpi->pr.pe->vaddr);

	return 1;
}

static int uffd_handle_pages(struct lazy_pages_info *lpi, __u64 address, int nr, unsigned flags)
{
	int ret;

	ret = uffd_seek_or_zero_pages(lpi, address, nr);
	if (ret <= 0)
		return ret;

	ret = lpi->pr.read_pages(&lpi->pr, address, nr, lpi->buf, flags);
	if (ret <= 0) {
		pr_err("%d-%d: failed reading pages at %llx\n", lpi->pid, lpi->lpfd.fd, address);
		return ret;
	}

	return 0;
}

static int handle_remaining_pages(struct lazy_pages_info *lpi)
{
	struct lazy_iovec *lazy_iov;
	int nr_pages, err;

	if (list_empty(&lpi->iovs))
		return 0;

	lazy_iov = list_first_entry(&lpi->iovs, struct lazy_iovec, l);
	nr_pages = lazy_iov->len / PAGE_SIZE;

	err = uffd_handle_pages(lpi, lazy_iov->base, nr_pages, 0);
	if (err < 0) {
		pr_err("Error during UFFD copy\n");
		return -1;
	}

	return 0;
}

static int handle_madv_dontneed(struct lazy_pages_info *lpi,
				struct uffd_msg *msg)
{
	struct uffdio_range unreg;

	unreg.start = msg->arg.madv_dn.start;
	unreg.len = msg->arg.madv_dn.end - msg->arg.madv_dn.start;

	if (ioctl(lpi->lpfd.fd, UFFDIO_UNREGISTER, &unreg)) {
		pr_perror("Failed to unregister (%llx - %llx)", unreg.start,
			  unreg.start + unreg.len);
		return -1;
	}

	if (update_lazy_iovecs(lpi, unreg.start, unreg.len))
		return -1;

	return 0;
}

static int handle_remap(struct lazy_pages_info *lpi, struct uffd_msg *msg)
{
	struct lazy_remap *remap;

	remap = xmalloc(sizeof(*remap));
	if (!remap)
		return -1;

	INIT_LIST_HEAD(&remap->l);
	remap->from = msg->arg.remap.from;
	remap->to = msg->arg.remap.to;
	remap->len = msg->arg.remap.len;
	list_add_tail(&remap->l, &lpi->remaps);

	return 0;
}

static int copy_remaps(struct lazy_pages_info *src, struct lazy_pages_info *dst)
{
	struct lazy_remap *p, *n, *new;

	list_for_each_entry(p, &src->remaps, l) {
		new = xmalloc(sizeof(*new));
		if (!new)
			goto free_remaps;

		new->from = p->from;
		new->to = p->to;
		new->len = p->len;

		list_add_tail(&new->l, &dst->remaps);
	}

	return 0;

free_remaps:
	list_for_each_entry_safe(p, n, &dst->remaps, l)
		xfree(p);
	return -1;
}

static int handle_fork(struct lazy_pages_info *parent_lpi, struct uffd_msg *msg)
{
	struct lazy_pages_info *lpi;
	int uffd = msg->arg.fork.ufd;

	pr_debug("%d-%d: child with ufd=%d\n", parent_lpi->pid, parent_lpi->lpfd.fd, uffd);

	lpi = lpi_init();
	if (!lpi)
		return -1;

	if (copy_lazy_iovecs(parent_lpi, lpi))
		goto out;

	if (copy_remaps(parent_lpi, lpi))
		goto out;

	lpi->pid = parent_lpi->pid;
	lpi->lpfd.fd = uffd;
	lpi->parent = parent_lpi->parent ? parent_lpi->parent : parent_lpi;
	lpi->copied_pages = lpi->parent->copied_pages;
	lpi->total_pages = lpi->parent->total_pages;
	list_add_tail(&lpi->l, &pending_lpis);

	dup_page_read(&lpi->parent->pr, &lpi->pr);

	return 1;

out:
	lpi_fini(lpi);
	return -1;
}

static int complete_forks(int epollfd, struct epoll_event **events, int *nr_fds)
{
	struct lazy_pages_info *lpi, *n;

	list_for_each_entry(lpi, &pending_lpis, l)
		(*nr_fds)++;

	*events = xrealloc(*events, sizeof(struct epoll_event) * (*nr_fds));
	if (!*events)
		return -1;

	list_for_each_entry_safe(lpi, n, &pending_lpis, l) {
		if (epoll_add_rfd(epollfd, &lpi->lpfd))
			return -1;

		list_del_init(&lpi->l);
		list_add_tail(&lpi->l, &lpis);
	}

	return 0;
}

static int handle_page_fault(struct lazy_pages_info *lpi, struct uffd_msg *msg)
{
	struct pf_info *pf;
	struct lazy_remap *r;
	__u64 address;
	int ret;

	/* Align requested address to the next page boundary */
	address = msg->arg.pagefault.address & ~(page_size() - 1);
	pr_debug("%d-%d: #PF at 0x%llx\n", lpi->pid, lpi->lpfd.fd, address);

#if 0
	/*
	 * Until uffd in kernel gets support for write protection,
	 * flags are always 0, so there is no point to read and print
	 * them
	 */
	{
	__u64 flags;

	/* Now handle the pages actually requested. */
	flags = msg.arg.pagefault.flags;
	pr_debug("msg.arg.pagefault.flags 0x%llx\n", flags);
	}
#endif

	list_for_each_entry(r, &lpi->remaps, l) {
		if (address >= r->to && address < r->to + r->len) {
			address -= (r->to - r->from);
			break;
		}
	}

	list_for_each_entry(pf, &lpi->pfs, l)
		if (pf->addr == address)
			return 0;

	pf = xzalloc(sizeof(*pf));
	if (!pf)
		return -1;
	pf->addr = address;
	list_add(&pf->l, &lpi->pfs);

	ret = uffd_handle_pages(lpi, address, 1, PR_ASYNC | PR_ASAP);
	if (ret < 0) {
		pr_err("Error during regular page copy\n");
		return -1;
	}

	return 0;
}

static int handle_uffd_event(struct epoll_rfd *lpfd)
{
	struct lazy_pages_info *lpi;
	struct uffd_msg msg;
	int ret;

	lpi = container_of(lpfd, struct lazy_pages_info, lpfd);

	ret = read(lpfd->fd, &msg, sizeof(msg));
	if (!ret)
		return 1;

	if (ret != sizeof(msg)) {
		/* we've already handled the page fault for another thread */
		if (errno == EAGAIN)
			return 0;
		if (ret < 0)
			pr_perror("Can't read userfaultfd message");
		else
			pr_err("Can't read userfaultfd message: short read");
		return -1;
	}

	switch (msg.event) {
	case UFFD_EVENT_PAGEFAULT:
		return handle_page_fault(lpi, &msg);
	case UFFD_EVENT_MADVDONTNEED:
		return handle_madv_dontneed(lpi, &msg);
	case UFFD_EVENT_REMAP:
		return handle_remap(lpi, &msg);
	case UFFD_EVENT_FORK:
		return handle_fork(lpi, &msg);
	default:
		pr_err("unexpected uffd event %u\n", msg.event);
		return -1;
	}

	return 0;
}

static int lazy_pages_summary(struct lazy_pages_info *lpi)
{
	pr_debug("%d-%d: with UFFD transferred pages: (%ld/%ld)\n",
		 lpi->pid, lpi->lpfd.fd, lpi->copied_pages, lpi->total_pages);

	if ((lpi->copied_pages != lpi->total_pages) && (lpi->total_pages > 0)) {
		pr_warn("Only %ld of %ld pages transferred via UFFD\n", lpi->copied_pages,
			lpi->total_pages);
		pr_warn("Something probably went wrong.\n");
		return 1;
	}

	return 0;
}

#define POLL_TIMEOUT 1000

static int handle_requests(int epollfd, struct epoll_event *events, int nr_fds)
{
	struct lazy_pages_info *lpi;
	int poll_timeout = POLL_TIMEOUT;
	int ret;

	for (;;) {
		bool remaining = false;

		ret = epoll_run_rfds(epollfd, events, nr_fds, poll_timeout);
		if (ret < 0)
			goto out;
		if (ret > 0) {
			if (complete_forks(epollfd, &events, &nr_fds))
				return -1;
			continue;
		}

		if (poll_timeout)
			pr_debug("Start handling remaining pages\n");

		poll_timeout = 0;
		list_for_each_entry(lpi, &lpis, l) {
			if (lpi->copied_pages < lpi->total_pages) {
				remaining = true;
				ret = handle_remaining_pages(lpi);
				if (ret < 0)
					goto out;
				break;
			}
		}

		if (!remaining)
			break;
	}

	list_for_each_entry(lpi, &lpis, l)
		ret += lazy_pages_summary(lpi);

out:
	return ret;

}

static int prepare_lazy_socket(void)
{
	int listen;
	struct sockaddr_un saddr;

	if (prepare_sock_addr(&saddr))
		return -1;

	pr_debug("Waiting for incoming connections on %s\n", saddr.sun_path);
	if ((listen = server_listen(&saddr)) < 0) {
		pr_perror("server_listen error");
		return -1;
	}

	return listen;
}

static int prepare_uffds(int listen, int epollfd)
{
	int i;
	int client;
	socklen_t len;
	struct sockaddr_un saddr;

	/* accept new client request */
	len = sizeof(struct sockaddr_un);
	if ((client = accept(listen, (struct sockaddr *) &saddr, &len)) < 0) {
		pr_perror("server_accept error");
		close(listen);
		return -1;
	}

	for (i = 0; i < task_entries->nr_tasks; i++) {
		struct lazy_pages_info *lpi = NULL;
		if (ud_open(client, &lpi))
			goto close_uffd;
		if (lpi == NULL)
			continue;
		if (epoll_add_rfd(epollfd, &lpi->lpfd))
			goto close_uffd;
	}

	close_safe(&client);
	close(listen);
	return 0;

close_uffd:
	close_safe(&client);
	close(listen);
	return -1;
}

int cr_lazy_pages(bool daemon)
{
	struct epoll_event *events;
	int epollfd;
	int nr_fds;
	int lazy_sk;
	int ret;

	if (kerndat_uffd(true))
		return -1;

	if (prepare_dummy_pstree())
		return -1;

	lazy_sk = prepare_lazy_socket();
	if (lazy_sk < 0)
		return -1;

	if (daemon) {
		ret = cr_daemon(1, 0, &lazy_sk, -1);
		if (ret == -1) {
			pr_err("Can't run in the background\n");
			return -1;
		}
		if (ret > 0) { /* parent task, daemon started */
			if (opts.pidfile) {
				if (write_pidfile(ret) == -1) {
					pr_perror("Can't write pidfile");
					kill(ret, SIGKILL);
					waitpid(ret, NULL, 0);
					return -1;
				}
			}

			return 0;
		}
	}

	nr_fds = task_entries->nr_tasks + (opts.use_page_server ? 1 : 0);
	epollfd = epoll_prepare(nr_fds, &events);
	if (epollfd < 0)
		return -1;

	if (prepare_uffds(lazy_sk, epollfd))
		return -1;

	if (opts.use_page_server) {
		if (connect_to_page_server_to_recv(epollfd))
			return -1;
	}

	ret = handle_requests(epollfd, events, nr_fds);

	return ret;
}
