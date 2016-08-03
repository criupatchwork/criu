#include <unistd.h>

#include "img-remote.h"
#include "img-remote-proto.h"
#include "criu-log.h"
#include <pthread.h>
#include <fcntl.h>
#include "cr_options.h"

int proxy_to_cache_fd;

static struct rimage *wait_for_image(struct wthread *wt)
{
	struct rimage *result;

	result = get_rimg_by_name(wt->snapshot_id, wt->path);
	if (result != NULL) {
		if (write_reply_header(wt->fd, 0) < 0) {
			pr_perror("Error writing reply header for %s:%s",
			    wt->path, wt->snapshot_id);
			close(wt->fd);
			return NULL;
		}
		return result;
	}

	/* The file does not exist. */
	else {
	    pr_info("No image %s:%s.\n", wt->path, wt->snapshot_id);
		if (write_reply_header(wt->fd, ENOENT) < 0) {
			pr_perror("Error writing reply header for unexisting image");
			return NULL;
		}
		close(wt->fd);
		return NULL;
	}
}

uint64_t forward_image(struct rimage *rimg)
{
	uint64_t ret;
	int fd = proxy_to_cache_fd;

	if (!strncmp(rimg->path, DUMP_FINISH, sizeof(DUMP_FINISH))) {
		finished = true;
		return 0;
		/* TODO - how to kill the accept thread? Close the accept fd? */
	}

	pthread_mutex_lock(&(rimg->in_use));
	if (write_remote_header(
		fd, rimg->snapshot_id, rimg->path, O_APPEND, rimg->size) < 0) {
		pr_perror("Error writing header for %s:%s",
			rimg->path, rimg->snapshot_id);
		pthread_mutex_unlock(&(rimg->in_use));
		return -1;
	}

	ret = send_image(fd, rimg, O_APPEND, false);
	if (ret < 0) {
		pr_perror("Unable to send %s:%s to image cache",
			rimg->path, rimg->snapshot_id);
		pthread_mutex_unlock(&(rimg->in_use));
		return -1;
	} else if (ret != rimg->size) {
		pr_perror("Unable to send %s:%s to image proxy (sent %lu bytes, expected %lu bytes",
		    rimg->path, rimg->snapshot_id, ret, rimg->size);
		pthread_mutex_unlock(&(rimg->in_use));
		return -1;
	}
	pthread_mutex_unlock(&(rimg->in_use));

	pr_info("Finished forwarding %s:%s (sent %lu bytes)\n",
	    rimg->path, rimg->snapshot_id, rimg->size);
	return ret;
}

int image_proxy(char *local_proxy_path, char *fwd_host, unsigned short fwd_port)
{
	pthread_t local_req_thr;
	int local_req_fd;

	pr_info("CRIU to Proxy Path: %s, Cache Address %s:%hu\n",
		local_proxy_path, fwd_host, fwd_port);

	local_req_fd = setup_UNIX_server_socket(local_proxy_path);
	if (local_req_fd < 0) {
		pr_perror("Unable to open CRIU to proxy UNIX socket");
		return -1;
	}

	if (opts.ps_socket != -1) {
		proxy_to_cache_fd = opts.ps_socket;
		pr_info("Re-using ps socket %d\n", proxy_to_cache_fd);
	} else {
		proxy_to_cache_fd = setup_TCP_client_socket(fwd_host, fwd_port);
		if (proxy_to_cache_fd < 0) {
			pr_perror("Unable to open proxy to cache TCP socket");
			return -1;
		}
	}

	if (init_daemon(wait_for_image))
		return -1;

	if (pthread_create(
	    &local_req_thr,
	    NULL,
	    accept_local_image_connections,
	    (void *) &local_req_fd)) {
		pr_perror("Unable to create local requests thread");
		return -1;
	}

	join_workers();

	pthread_join(local_req_thr, NULL);
	return 0;
}
