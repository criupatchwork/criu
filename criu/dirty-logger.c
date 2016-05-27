#include <pthread.h>
#include <sys/time.h>
#include <unistd.h>

#include "imgset.h"
#include "pstree.h"
#include "protobuf.h"
#include "util.h"
#include "mem.h"

#include "images/stats.pb-c.h"

#define NSEC_PER_USEC	1000L
#define USEC_PER_SEC	1000000L

static int sleep_us(long us) {
	struct timespec ts, rts;
	ts.tv_sec = us / USEC_PER_SEC;
	ts.tv_nsec = NSEC_PER_USEC * (us % USEC_PER_SEC);
	while (nanosleep(&ts, &rts)) {
		if (errno != EINTR)
			return -1;
		ts = rts;
	}

	return 0;
}

void fd_cleanup(void *arg)
{
       close(*(int *)arg);
}

void fp_cleanup(void *arg)
{
       fclose((FILE *)arg);
}

void img_cleanup(void *arg)
{
       close_image((struct cr_img *)arg);
}

#define MAPS_PATH "/proc/%d/maps"
#define MAX_MAPS_PATH 50
#define BUFF_SIZE 500000
#define LINELEN 256

static int pid_log_dirty_total(pid_t pid, long *total_pages, long *total_dirty_pages)
{
	char maps_path[MAX_MAPS_PATH];
	FILE * maps;
	int pagemap_fd;

	u64 pfn[BUFF_SIZE];
	char line[LINELEN];

	sprintf(maps_path, MAPS_PATH, pid);
	maps = fopen(maps_path, "r");
	if (maps == NULL) {
		pr_perror("Can't open pid %d maps", pid);
		return -1;
	}
	pthread_cleanup_push(fp_cleanup, (void *)maps);

	pagemap_fd = open_proc(pid, "pagemap");
	if (pagemap_fd < 0) {
		pr_perror("Can't open pid %d pagemap", pid);
		return -1;
	}
	pthread_cleanup_push(fd_cleanup, (void *)&pagemap_fd);

	/*
	 * For each line in maps
	 */
	while (fgets(line, LINELEN, maps) != NULL) {
		char * pend;
		uint64_t start, end;
		off_t off;
		long j;
		int ret;

		start = strtoul(line, &pend, 16);
		end = strtoul(pend + 1, NULL, 16);
		if (start >= end)
			continue;

		off = (start / PAGE_SIZE) * sizeof(u64);
		pr_debug("Read pagemap from %"PRIx64" to %"PRIx64"\n", start, end);
		if (lseek (pagemap_fd, off, SEEK_SET) != off) {
			pr_perror("Failed to seek address %"PRIx64"\n", off);
			return -1;
		}

		if ((end - start) / PAGE_SIZE > BUFF_SIZE) {
			pr_err("Buffer overflow for pid %d\n", pid);
			return -1;
		}

		ret = read(pagemap_fd, pfn, ((end - start) / PAGE_SIZE) * sizeof(u64));
		if (ret != ((end - start) / PAGE_SIZE) * sizeof(u64)) {
			if (ret == 0) {
				pr_debug("Can't read because of EOF\n");
				continue;
			}
			pr_perror("Can't read pme for pid %d", pid);
			return -1;
		}

		*total_pages += ret/sizeof(u64);
		for (j = 0; j < ret/sizeof(u64); j++) {
			if (pfn[j] & PME_SOFT_DIRTY) {
				(*total_dirty_pages)++;
			}
		}
		pr_debug("Pid %d: %ld pages read, %ld dirty\n", pid, *total_pages, *total_dirty_pages);
	}

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	return 0;
}

static int log_dirty_total(struct cr_img *img, struct timeval *start)
{
	struct pstree_item *item;
	long total_pages = 0;
	long total_dirty_pages = 0;
	struct timeval tv;
	int ret;
	DirtyLogEntry dle = DIRTY_LOG_ENTRY__INIT;

	/*
	 * Calculate dirty pages total cout across the tree
	 */
	for_each_pstree_item(item) {
		if (pid_log_dirty_total(item->pid.real, &total_pages, &total_dirty_pages))
			return -1;
	}

	ret = gettimeofday(&tv, NULL);
	if (ret == -1) {
		pr_perror("Failed gettimeofday");
		return -1;
	}
	timediff(start, &tv);

	dle.sec = tv.tv_sec;
	dle.usec = tv.tv_usec;
	dle.total_pages = total_pages;
	dle.total_dirty_pages = total_dirty_pages;

	ret = pb_write_one(img, &dle, PB_DIRTY_LOG);
	if (ret == -1) {
		pr_perror("Failed pb_write_one");
		return -1;
	}

	return 0;
}

#define CR_DIRTY_LOG "dirty-log.img"

#define INC_ITER_TIME 1.5

void *dirty_logger_pthread(void *arg)
{
	int *pret = (int *)arg;
	struct cr_img *img;
	long double next_iter_time = 0;
	struct timeval start;
	int ret;

	ret = gettimeofday(&start, NULL);
	if (ret == -1) {
		pr_perror("Failed gettimeofday");
		*pret = -1;
		pthread_exit(NULL);
	}

	img = open_image_at(AT_FDCWD, CR_FD_DIRTY_LOG, O_DUMP);
	if (!img) {
		*pret = -1;
		pthread_exit(NULL);
	}
	pthread_cleanup_push(img_cleanup, (void *)img);

	while(1) {
		struct timeval iter_start, iter_end;
		long sleep_time;

		ret = gettimeofday(&iter_start, NULL);
		if (ret == -1) {
			pr_perror("Failed gettimeofday");
			*pret = -1;
			pthread_exit(NULL);
		}

		ret = log_dirty_total(img, &start);
		if (ret == -1) {
			*pret = -1;
			pthread_exit(NULL);
		}

		ret = gettimeofday(&iter_end, NULL);
		if (ret == -1) {
			pr_perror("Failed gettimeofday");
			*pret = -1;
			pthread_exit(NULL);
		}

		timediff(&iter_start, &iter_end);

		if (!next_iter_time)
			next_iter_time = iter_end.tv_sec * USEC_PER_SEC
				+ iter_end.tv_usec;

		sleep_time = next_iter_time - (iter_end.tv_sec * USEC_PER_SEC
				+ iter_end.tv_usec);
		if (sleep_time <= 0)
			continue;

		ret = sleep_us((long)sleep_time);
		if (ret == -1) {
			pr_perror("Failed sleep_us");
			*pret = -1;
			pthread_exit(NULL);
		}
		next_iter_time *= INC_ITER_TIME;
	}

	*pret = 0;
	pthread_cleanup_pop(1);
	pthread_exit(NULL);
}
