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
#define LOG_PREFIX "uffd: "

#define lp_debug(lpi, fmt, arg...) pr_debug("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)
#define lp_info(lpi, fmt, arg...) pr_info("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)
#define lp_warn(lpi, fmt, arg...) pr_warn("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)
#define lp_err(lpi, fmt, arg...) pr_err("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)
#define lp_perror(lpi, fmt, arg...) pr_perror("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)

#define LAZY_PAGES_SOCK_NAME	"lazy-pages.socket"

static mutex_t *lazy_sock_mutex;

struct lazy_iov {
	struct list_head l;
	unsigned long base;
	unsigned long len;
};

struct lazy_pages_info;

struct lp_req {
	unsigned long addr;
	struct list_head l;
};

struct lazy_pages_info {
	int pid;

	struct list_head iovs;
	struct list_head reqs;

	struct page_read pr;

	unsigned long total_pages;
	unsigned long copied_pages;

	struct epoll_rfd lpfd;

	struct list_head l;

	void *buf;
};

static LIST_HEAD(lpis);
static int handle_uffd_event(struct epoll_rfd *lpfd);

static struct lazy_pages_info *lpi_init(void)
{
	struct lazy_pages_info *lpi = NULL;

	lpi = xmalloc(sizeof(*lpi));
	if (!lpi)
		return NULL;

	memset(lpi, 0, sizeof(*lpi));
	INIT_LIST_HEAD(&lpi->iovs);
	INIT_LIST_HEAD(&lpi->reqs);
	INIT_LIST_HEAD(&lpi->l);
	lpi->lpfd.revent = handle_uffd_event;

	return lpi;
}

static void lpi_fini(struct lazy_pages_info *lpi)
{
	struct lazy_iov *p, *n;

	if (!lpi)
		return;
	free(lpi->buf);
	list_for_each_entry_safe(p, n, &lpi->iovs, l)
		xfree(p);
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
	lp_debug(lpi, "Found %zd VMAs in image\n", mm->n_vmas);

	return mm;
}

static struct lazy_iov *find_lazy_iov(struct lazy_pages_info *lpi,
				      unsigned long addr)
{
	struct lazy_iov *iov;

	list_for_each_entry(iov, &lpi->iovs, l)
		if (addr >= iov->base && addr < iov->base + iov->len)
			return iov;

	return NULL;
}

/*
 * Purge range (addr, addr + len) from lazy_iovs. The range may
 * cover several continuous IOVs.
 */
static int update_lazy_iovs(struct lazy_pages_info *lpi, unsigned long addr,
			    int len)
{
	struct lazy_iov *iov, *n;

	list_for_each_entry_safe(iov, n, &lpi->iovs, l) {
		unsigned long start = iov->base;
		unsigned long end = start + iov->len;

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
				iov->base += len;
				iov->len -= len;
			} else {
				struct lazy_iov *new_iov;

				iov->len -= (end - addr);

				new_iov = xzalloc(sizeof(*new_iov));
				if (!new_iov)
					return -1;

				new_iov->base = addr + len;
				new_iov->len = end - (addr + len);

				list_add(&new_iov->l, &iov->l);
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
			list_del(&iov->l);
			xfree(iov);
		} else {
			iov->len -= (end - addr);
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
static int collect_lazy_iovs(struct lazy_pages_info *lpi)
{
	struct page_read *pr = &lpi->pr;
	struct lazy_iov *iov, *n;
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

			iov = xzalloc(sizeof(*iov));
			if (!iov)
				goto free_iovs;

			len = min_t(uint64_t, end, vma->end) - start;
			iov->base = start;
			iov->len = len;
			list_add_tail(&iov->l, &lpi->iovs);

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
	list_for_each_entry_safe(iov, n, &lpi->iovs, l)
		xfree(iov);
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
	ret = collect_lazy_iovs(lpi);
	if (ret < 0)
		goto out;
	lpi->total_pages = ret;

	lp_debug(lpi, "Found %ld pages to be handled by UFFD\n", lpi->total_pages);

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
	unsigned long len = nr_pages * page_size();
	int rc;

	uffdio_copy.dst = address;
	uffdio_copy.src = (unsigned long)lpi->buf;
	uffdio_copy.len = len;
	uffdio_copy.mode = 0;
	uffdio_copy.copy = 0;

	lp_debug(lpi, "uffd_copy: 0x%llx/%ld\n", uffdio_copy.dst, len);
	rc = ioctl(lpi->lpfd.fd, UFFDIO_COPY, &uffdio_copy);
	if (rc) {
		/* real retval in ufdio_copy.copy */
		lp_err(lpi, "UFFDIO_COPY failed: rc:%d copy:%Ld\n", rc,
		       uffdio_copy.copy);
		if (uffdio_copy.copy != -EEXIST)
			return -1;
	} else if (uffdio_copy.copy != len) {
		lp_err(lpi, "UFFDIO_COPY unexpected size %Ld\n", uffdio_copy.copy);
		return -1;
	}

	lpi->copied_pages += nr_pages;

	return 0;
}

static int complete_page_fault(struct lazy_pages_info *lpi, unsigned long vaddr, int nr)
{
	struct lp_req *req;

	if (uffd_copy(lpi, vaddr, nr))
		return -1;

	list_for_each_entry(req, &lpi->reqs, l) {
		if (req->addr == vaddr) {
			list_del(&req->l);
			xfree(req);
			break;
		}
	}

	return update_lazy_iovs(lpi, vaddr, nr * PAGE_SIZE);
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

	lp_debug(lpi, "zero page at 0x%llx\n", address);
	rc = ioctl(lpi->lpfd.fd, UFFDIO_ZEROPAGE, &uffdio_zeropage);
	if (rc) {
		lp_err(lpi, "UFFDIO_ZEROPAGE error %d\n", rc);
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
static int uffd_seek_pages(struct lazy_pages_info *lpi, __u64 address, int nr)
{
	int ret;

	lpi->pr.reset(&lpi->pr);

	ret = lpi->pr.seek_pagemap(&lpi->pr, address);
	if (!ret) {
		lp_err(lpi, "no pagemap covers %llx\n", address);
		return ret;
	}

	lpi->pr.skip_pages(&lpi->pr, address - lpi->pr.pe->vaddr);

	return 0;
}

static int uffd_handle_pages(struct lazy_pages_info *lpi, __u64 address, int nr, unsigned flags)
{
	int ret;

	ret = uffd_seek_pages(lpi, address, nr);
	if (ret)
		return ret;

	ret = lpi->pr.read_pages(&lpi->pr, address, nr, lpi->buf, flags);
	if (ret <= 0) {
		lp_err(lpi, "failed reading pages at %llx\n", address);
		return ret;
	}

	return 0;
}

static int handle_remaining_pages(struct lazy_pages_info *lpi)
{
	struct lazy_iov *iov;
	int nr_pages, err;

	if (list_empty(&lpi->iovs))
		return 0;

	iov = list_first_entry(&lpi->iovs, struct lazy_iov, l);
	nr_pages = iov->len / PAGE_SIZE;

	err = uffd_handle_pages(lpi, iov->base, nr_pages, 0);
	if (err < 0) {
		lp_err(lpi, "Error during UFFD copy\n");
		return -1;
	}

	return 0;
}

static int handle_page_fault(struct lazy_pages_info *lpi, struct uffd_msg *msg)
{
	struct lp_req *req;
	struct lazy_iov *iov;
	__u64 address;
	int ret;

	/* Align requested address to the next page boundary */
	address = msg->arg.pagefault.address & ~(page_size() - 1);
	lp_debug(lpi, "#PF at 0x%llx\n", address);

	list_for_each_entry(req, &lpi->reqs, l)
		if (req->addr == address)
			return 0;

	iov = find_lazy_iov(lpi, address);
	if (!iov)
		return uffd_zero(lpi, address, 1);

	req = xzalloc(sizeof(*req));
	if (!req)
		return -1;
	req->addr = address;
	list_add(&req->l, &lpi->reqs);

	ret = uffd_handle_pages(lpi, address, 1, PR_ASYNC | PR_ASAP);
	if (ret < 0) {
		lp_err(lpi, "Error during regular page copy\n");
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
			lp_perror(lpi, "Can't read uffd message");
		else
			lp_err(lpi, "Can't read uffd message: short read");
		return -1;
	}

	switch (msg.event) {
	case UFFD_EVENT_PAGEFAULT:
		return handle_page_fault(lpi, &msg);
	default:
		lp_err(lpi, "unexpected uffd event %u\n", msg.event);
		return -1;
	}

	return 0;
}

static int lazy_pages_summary(struct lazy_pages_info *lpi)
{
	lp_debug(lpi, "UFFD transferred pages: (%ld/%ld)\n",
		 lpi->copied_pages, lpi->total_pages);

	if ((lpi->copied_pages != lpi->total_pages) && (lpi->total_pages > 0)) {
		lp_warn(lpi, "Only %ld of %ld pages transferred via UFFD\n"
			"Something probably went wrong.\n",
			lpi->copied_pages, lpi->total_pages);
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

	if (close_status_fd())
		return -1;

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
