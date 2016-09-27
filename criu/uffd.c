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
#include <sys/epoll.h>

#include "linux/userfaultfd.h"

#include "asm/page.h"
#include "log.h"
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
#include "uapi/std/syscall-codes.h"
#include "restorer.h"
#include "page-xfer.h"
#include "lock.h"
#include "rst-malloc.h"

#undef  LOG_PREFIX
#define LOG_PREFIX "lazy-pages: "

#define LAZY_PAGES_SOCK_NAME	"lazy-pages.socket"

static mutex_t *lazy_sock_mutex;

struct lazy_iovec {
	struct iovec iov;
	struct list_head l;
};

struct lazy_pages_info {
	int pid;
	int uffd;

	struct list_head iovs;

	struct page_read pr;

	unsigned long total_pages;
	unsigned long copied_pages;

	struct hlist_node hash;

	void *buf;
};

#define LPI_HASH_SIZE	16
static struct hlist_head lpi_hash[LPI_HASH_SIZE];

static struct lazy_pages_info *lpi_init(void)
{
	struct lazy_pages_info *lpi = NULL;

	lpi = malloc(sizeof(*lpi));
	if (!lpi) {
		pr_err("allocation failed\n");
		return NULL;
	}

	memset(lpi, 0, sizeof(*lpi));
	INIT_LIST_HEAD(&lpi->iovs);
	INIT_HLIST_NODE(&lpi->hash);

	return lpi;
}

static void lpi_fini(struct lazy_pages_info *lpi)
{
	struct lazy_iovec *p, *n;

	if (!lpi)
		return;
	list_for_each_entry_safe(p, n, &lpi->iovs, l)
		xfree(p);
	if (lpi->uffd > 0)
		close(lpi->uffd);
	if (lpi->pr.close)
		lpi->pr.close(&lpi->pr);
	free(lpi);
}

static void lpi_hash_init(void)
{
	int i;

	for (i = 0; i < LPI_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&lpi_hash[i]);
}

struct lazy_pages_info *uffd_to_lpi(int uffd)
{
	struct lazy_pages_info *lpi;
	struct hlist_head *head;

	head = &lpi_hash[uffd % LPI_HASH_SIZE];
	hlist_for_each_entry(lpi, head, hash)
		if (lpi->uffd == uffd)
			return lpi;

	return NULL;
}

static void lpi_hash_fini(void)
{
	struct lazy_pages_info *p;
	struct hlist_node *n;
	int i;

	for (i = 0; i < LPI_HASH_SIZE; i++)
		hlist_for_each_entry_safe(p, n, &lpi_hash[i], hash)
			lpi_fini(p);
}

static int prepare_sock_addr(struct sockaddr_un *saddr)
{
	char cwd[PATH_MAX];
	int len;

	if (!getcwd(cwd, PATH_MAX)) {
		pr_perror("Cannot get CWD\n");
		return -1;
	}

	memset(saddr, 0, sizeof(struct sockaddr_un));

	saddr->sun_family = AF_UNIX;
	len = snprintf(saddr->sun_path, sizeof(saddr->sun_path),
		       "%s/%s", cwd, LAZY_PAGES_SOCK_NAME);
	if (len >= sizeof(saddr->sun_path)) {
		pr_err("Wrong UNIX socket name: %s/%s\n",
		       cwd, LAZY_PAGES_SOCK_NAME);
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
		pr_perror("PID sending error:");
		goto out;
	}

	if (send_fd(fd, NULL, 0, sendfd) < 0) {
		pr_perror("send_fd error:");
		goto out;
	}

	mutex_unlock(lazy_sock_mutex);

	ret = 0;
out:
	close(fd);
	return ret;
}

/* Runtime detection if userfaultfd can be used */

static int check_for_uffd()
{
	int uffd;

	uffd = syscall(SYS_userfaultfd, 0);
	/*
	 * uffd == -1 is probably enough to not use lazy-restore
	 * on this system. Additionally checking for ENOSYS
	 * makes sure it is actually not implemented.
	 */
	if ((uffd == -1) && (errno == ENOSYS)) {
		pr_err("Runtime detection of userfaultfd failed on this system.\n");
		pr_err("Processes cannot be lazy-restored on this system.\n");
		return -1;
	}
	close(uffd);
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

	if (check_for_uffd())
		return -1;
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

static int update_lazy_iovecs(struct lazy_pages_info *lpi, unsigned long addr,
			       int len)
{
	struct lazy_iovec *lazy_iov, *n;

	list_for_each_entry_safe(lazy_iov, n, &lpi->iovs, l) {
		unsigned long start = (unsigned long)lazy_iov->iov.iov_base;
		unsigned long end = start + lazy_iov->iov.iov_len;

		if (len <= 0)
			break;

		if (addr < start || addr >= end)
			continue;

		if (addr + len < end) {
			if (addr == start) {
				lazy_iov->iov.iov_base += len;
				lazy_iov->iov.iov_len -= len;
			} else {
				struct lazy_iovec *new;

				lazy_iov->iov.iov_len -= (end - addr);

				new = xzalloc(sizeof(*new));
				if (!new)
					return -1;

				new->iov.iov_base = (void *)(addr + len);
				new->iov.iov_len = end - (addr + len);

				list_add(&new->l, &lazy_iov->l);
			}
			break;
		}

		if (addr == start) {
			list_del(&lazy_iov->l);
			xfree(lazy_iov);
		} else {
			lazy_iov->iov.iov_len -= (end - addr);
		}

		len -= (end - addr);
		addr = end;
	}

	return 0;
}

static int collect_lazy_iovecs(struct lazy_pages_info *lpi)
{
	struct page_read *pr = &lpi->pr;
	struct lazy_iovec *lazy_iov, *n;
	int nr_pages = 0, max_iov_len = 0;

	pr->reset(pr);

	while (pr->advance(pr)) {
		PagemapEntry *pe = pr->pe;

		if (!pagemap_lazy(pe))
			continue;

		lazy_iov = xzalloc(sizeof(*lazy_iov));
		if (!lazy_iov) {
			pr_err("Out of memory\n");
			goto free_iovs;
		}

		pagemap2iovec(pe, &lazy_iov->iov);
		list_add_tail(&lazy_iov->l, &lpi->iovs);
		nr_pages += pe->nr_pages;

		if (lazy_iov->iov.iov_len > max_iov_len)
			max_iov_len = lazy_iov->iov.iov_len;

		pr_debug("adding IOV: %p:%lx (%d)\n", lazy_iov->iov.iov_base, lazy_iov->iov.iov_len, pe->nr_pages);
	}

	if (posix_memalign(&lpi->buf, PAGE_SIZE, max_iov_len))
		goto free_iovs;

	return nr_pages;

free_iovs:
	list_for_each_entry_safe(lazy_iov, n, &lpi->iovs, l)
		xfree(lazy_iov);

	return -1;
}

static struct lazy_pages_info *ud_open(int client)
{
	struct lazy_pages_info *lpi;
	int ret = -1;
	int uffd_flags;

	lpi = lpi_init();
	if (!lpi)
		goto out;

	/* The "transfer protocol" is first the pid as int and then
	 * the FD for UFFD */
	ret = recv(client, &lpi->pid, sizeof(lpi->pid), 0);
	if (ret != sizeof(lpi->pid)) {
		pr_perror("PID recv error:");
		goto out;
	}
	pr_debug("received PID: %d\n", lpi->pid);

	lpi->uffd = recv_fd(client);
	if (lpi->uffd < 0) {
		pr_perror("recv_fd error:");
		goto out;
	}
	pr_debug("lpi->uffd %d\n", lpi->uffd);

	pr_debug("uffd is 0x%d\n", lpi->uffd);
	uffd_flags = fcntl(lpi->uffd, F_GETFD, NULL);
	pr_debug("uffd_flags are 0x%x\n", uffd_flags);

	ret = open_page_read(lpi->pid, &lpi->pr, PR_TASK);
	if (ret <= 0) {
		ret = -1;
		goto out;
	}

	/*
	 * Find the memory pages belonging to the restored process
	 * so that it is trackable when all pages have been transferred.
	 */
	lpi->total_pages = collect_lazy_iovecs(lpi);
	if (lpi->total_pages < 0)
		goto out;

	pr_debug("Found %ld pages to be handled by UFFD\n", lpi->total_pages);

	hlist_add_head(&lpi->hash, &lpi_hash[lpi->uffd % LPI_HASH_SIZE]);

	ret = collect_lazy_iovecs(lpi);
	if (ret != lpi->total_pages) {
		pr_err("collect_lazy_iovecs=%d\n", ret);
		goto out;
	}

	return lpi;

out:
	lpi_fini(lpi);
	return NULL;
}

static int get_pages(struct lazy_pages_info *lpi, unsigned long addr, int nr)
{
	int ret;

	lpi->pr.reset(&lpi->pr);

	ret = lpi->pr.seek_page(&lpi->pr, addr, true);
	pr_debug("seek_pagemap_page ret 0x%x\n", ret);
	if (ret <= 0)
		return ret;

	if (pagemap_zero(lpi->pr.pe))
		return 0;

	ret = lpi->pr.read_pages(&lpi->pr, addr, nr, lpi->buf);
	pr_debug("read_pages ret %d\n", ret);
	if (ret <= 0)
		return ret;

	return nr;
}

static int uffd_copy(struct lazy_pages_info *lpi, __u64 address, int nr_pages)
{
	struct uffdio_copy uffdio_copy;
	unsigned long len = nr_pages * page_size();
	int rc;

	if (opts.use_page_server)
		rc = get_remote_pages(lpi->pid, address, 1, lpi->buf);
	else
		rc = get_pages(lpi, address, nr_pages);
	if (rc <= 0)
		return rc;

	uffdio_copy.dst = address;
	uffdio_copy.src = (unsigned long)lpi->buf;
	uffdio_copy.len = len;
	uffdio_copy.mode = 0;
	uffdio_copy.copy = 0;

	pr_debug("uffdio_copy.dst 0x%llx\n", uffdio_copy.dst);
	rc = ioctl(lpi->uffd, UFFDIO_COPY, &uffdio_copy);
	pr_debug("ioctl UFFDIO_COPY rc 0x%x\n", rc);
	pr_debug("uffdio_copy.copy 0x%llx\n", uffdio_copy.copy);
	if (rc) {
		/* real retval in ufdio_copy.copy */
		if (uffdio_copy.copy != -EEXIST) {
			pr_err("UFFDIO_COPY error %Ld\n", uffdio_copy.copy);
			return -1;
		}
	} else if (uffdio_copy.copy != len) {
		pr_err("UFFDIO_COPY unexpected size %Ld\n", uffdio_copy.copy);
		return -1;
	}

	lpi->copied_pages += nr_pages;

	return uffdio_copy.copy;
}

static int uffd_zero(struct lazy_pages_info *lpi, __u64 address, int nr_pages)
{
	struct uffdio_zeropage uffdio_zeropage;
	unsigned long len = page_size() * nr_pages;
	int rc;

	uffdio_zeropage.range.start = address;
	uffdio_zeropage.range.len = len;
	uffdio_zeropage.mode = 0;

	pr_debug("uffdio_zeropage.range.start 0x%llx\n", uffdio_zeropage.range.start);
	rc = ioctl(lpi->uffd, UFFDIO_ZEROPAGE, &uffdio_zeropage);
	pr_debug("ioctl UFFDIO_ZEROPAGE rc 0x%x\n", rc);
	pr_debug("uffdio_zeropage.zeropage 0x%llx\n", uffdio_zeropage.zeropage);
	if (rc) {
		pr_err("UFFDIO_ZEROPAGE error %d\n", rc);
		return -1;
	}

	return len;
}

static int uffd_handle_pages(struct lazy_pages_info *lpi, __u64 address, int nr)
{
	int rc;

	rc = uffd_copy(lpi, address, nr);
	if (rc == 0)
		rc = uffd_zero(lpi, address, nr);

	return rc;
}

static int handle_remaining_pages(struct lazy_pages_info *lpi)
{
	struct lazy_iovec *lazy_iov;
	int nr_pages, i, err;
	unsigned long base, addr;

	lpi->pr.reset(&lpi->pr);

	list_for_each_entry(lazy_iov, &lpi->iovs, l) {
		nr_pages = lazy_iov->iov.iov_len / PAGE_SIZE;
		base = (unsigned long)lazy_iov->iov.iov_base;

		for (i = 0; i < nr_pages; i++) {
			addr = base + i * PAGE_SIZE;

			err = uffd_handle_pages(lpi, addr, 1);
			if (err < 0) {
				pr_err("Error during UFFD copy\n");
				return -1;
			}
		}
	}

	return 0;
}

static int handle_regular_pages(struct lazy_pages_info *lpi, __u64 address,
				int nr)
{
	int rc;

	rc = uffd_handle_pages(lpi, address, nr);
	if (rc < 0) {
		pr_err("Error during UFFD copy\n");
		return -1;
	}

	rc = update_lazy_iovecs(lpi, address, PAGE_SIZE * nr);
	if (rc < 0)
		return -1;

	return 0;
}

static int handle_user_fault(struct lazy_pages_info *lpi)
{
	struct uffd_msg msg;
	__u64 flags;
	__u64 address;
	int ret;

	ret = read(lpi->uffd, &msg, sizeof(msg));
	pr_debug("read() ret: 0x%x\n", ret);
	if (!ret)
		return 1;

	if (ret != sizeof(msg)) {
		pr_perror("Can't read userfaultfd message");
		return -1;
	}

	/* Align requested address to the next page boundary */
	address = msg.arg.pagefault.address & ~(page_size() - 1);
	pr_debug("msg.arg.pagefault.address 0x%llx\n", address);

	/* Now handle the pages actually requested. */
	flags = msg.arg.pagefault.flags;
	pr_debug("msg.arg.pagefault.flags 0x%llx\n", flags);

	if (msg.event != UFFD_EVENT_PAGEFAULT) {
		pr_err("unexpected msg event %u\n", msg.event);
		return -1;
	}

	ret = handle_regular_pages(lpi, address, 1);
	if (ret < 0) {
		pr_err("Error during regular page copy\n");
		return -1;
	}

	return 0;
}

static int lazy_pages_summary(struct lazy_pages_info *lpi)
{
	pr_debug("Process %d: with UFFD transferred pages: (%ld/%ld)\n",
		 lpi->pid, lpi->copied_pages, lpi->total_pages);

	if ((lpi->copied_pages != lpi->total_pages) && (lpi->total_pages > 0)) {
		pr_warn("Only %ld of %ld pages transferred via UFFD\n", lpi->copied_pages,
			lpi->total_pages);
		pr_warn("Something probably went wrong.\n");
		return 1;
	}

	return 0;
}

#define POLL_TIMEOUT 5000

static int handle_requests(int epollfd, struct epoll_event *events)
{
	int nr_fds = task_entries->nr_tasks;
	struct lazy_pages_info *lpi;
	int ret = -1;
	int i;

	while (1) {
		/*
		 * Setting the timeout to 5 seconds. If after this time
		 * no uffd pages are requested the code switches to
		 * copying the remaining pages.
		 */
		ret = epoll_wait(epollfd, events, nr_fds, POLL_TIMEOUT);
		pr_debug("epoll() ret: 0x%x\n", ret);
		if (ret < 0) {
			pr_perror("polling failed");
			goto out;
		} else if (ret == 0) {
			pr_debug("read timeout\n");
			pr_debug("switching from request to copy mode\n");
			break;
		}

		for (i = 0; i < ret; i++) {
			int err;
			lpi = uffd_to_lpi(events[i].data.fd);
			BUG_ON(!lpi);
			err = handle_user_fault(lpi);
			if (err < 0)
				goto out;
		}
	}
	pr_debug("Handle remaining pages\n");
	for (i = 0; i < LPI_HASH_SIZE; i++) {
		hlist_for_each_entry(lpi, &lpi_hash[i], hash) {
			ret = handle_remaining_pages(lpi);
			if (ret < 0) {
				pr_err("Error during remaining page copy\n");
				ret = 1;
				goto out;
			}
		}
	}

	for (i = 0; i < LPI_HASH_SIZE; i++)
		hlist_for_each_entry(lpi, &lpi_hash[i], hash)
			ret += lazy_pages_summary(lpi);

out:
	return ret;

}

static int lazy_pages_prepare_pstree(void)
{
	if (check_img_inventory() == -1)
		return -1;

	/* Allocate memory for task_entries */
	if (prepare_task_entries() == -1)
		return -1;

	if (prepare_pstree() == -1)
		return -1;

	return 0;
}

static int prepare_epoll(int nr_fds, struct epoll_event **events)
{
	int epollfd;

	*events = malloc(sizeof(struct epoll_event) * nr_fds);
	if (!*events) {
		pr_err("memory allocation failed\n");
		return -1;
	}

	epollfd = epoll_create(nr_fds);
	if (epollfd == -1) {
		pr_perror("epoll_create failed");
		goto free_events;
	}

	return epollfd;

free_events:
	free(*events);
	return -1;
}

static int epoll_add_fd(int epollfd, int fd)
{
	struct epoll_event ev;

	ev.events = EPOLLIN;
	ev.data.fd = fd;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		pr_perror("epoll_ctl failed");
		return -1;
	}

	return 0;
}

static int prepare_uffds(int epollfd)
{
	int i;
	int listen;
	int client;
	socklen_t len;
	struct sockaddr_un saddr;

	if (prepare_sock_addr(&saddr))
		return -1;

	pr_debug("Waiting for incoming connections on %s\n", saddr.sun_path);
	if ((listen = server_listen(&saddr)) < 0) {
		pr_perror("server_listen error");
		return -1;
	}

	/* accept new client request */
	len = sizeof(struct sockaddr_un);
	if ((client = accept(listen, (struct sockaddr *) &saddr, &len)) < 0) {
		pr_perror("server_accept error: %d", client);
		close(listen);
		return -1;
	}
	pr_debug("client fd %d\n", client);

	for (i = 0; i < task_entries->nr_tasks; i++) {
		struct lazy_pages_info *lpi;
		lpi = ud_open(client);
		if (!lpi)
			goto close_uffd;
		if (epoll_add_fd(epollfd, lpi->uffd))
			goto close_uffd;
	}

	close_safe(&client);
	close(listen);
	return 0;

close_uffd:
	lpi_hash_fini();
	close_safe(&client);
	close(listen);
	return -1;
}

int cr_lazy_pages()
{
	struct epoll_event *events;
	int epollfd;
	int ret;

	if (check_for_uffd())
		return -1;

	lpi_hash_init();

	if (lazy_pages_prepare_pstree())
		return -1;

	epollfd = prepare_epoll(task_entries->nr_tasks, &events);
	if (epollfd < 0)
		return -1;

	if (prepare_uffds(epollfd))
		return -1;

	if (connect_to_page_server())
		return -1;

	ret = handle_requests(epollfd, events);
	lpi_hash_fini();

	return ret;
}
