#include <unistd.h>

#include "img-remote.h"
#include "criu-log.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include "cr_options.h"

int accept_proxy_to_cache(int sockfd)
{
	struct sockaddr_in cli_addr;
	socklen_t clilen = sizeof(cli_addr);
	int proxy_fd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

	if (proxy_fd < 0) {
		pr_perror("Unable to accept remote image connection from image proxy");
		return -1;
	}

	return proxy_fd;
}

int setup_TCP_server_socket(int port)
{
	struct sockaddr_in serv_addr;
	int sockopt = 1;
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd < 0) {
		pr_perror("Unable to open image socket");
		return -1;
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);

	if (setsockopt(
		sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) == -1) {
		pr_perror("Unable to set SO_REUSEADDR");
		goto err;
	}

	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		pr_perror("Unable to bind image socket");
		goto err;
	}

	if (listen(sockfd, DEFAULT_LISTEN)) {
		pr_perror("Unable to listen image socket");
		goto err;
	}

	return sockfd;
err:
	close(sockfd);
	return -1;
}

int image_cache(bool background, char *local_cache_path, unsigned short cache_write_port)
{
	pr_info("Proxy to Cache Port %d, CRIU to Cache Path %s\n",
			cache_write_port, local_cache_path);
	restoring = true;

	if (opts.ps_socket != -1) {
		proxy_to_cache_fd = opts.ps_socket;
		pr_info("Re-using ps socket %d\n", proxy_to_cache_fd);
	} else {
		proxy_to_cache_fd = setup_TCP_server_socket(cache_write_port);
		if (proxy_to_cache_fd < 0) {
			pr_perror("Unable to open proxy to cache TCP socket");
			return -1;
		}
		// Wait to accept connection from proxy.
		proxy_to_cache_fd = accept_proxy_to_cache(proxy_to_cache_fd);
		if (proxy_to_cache_fd < 0)
			return -1; // TODO - should close other sockets.
	}

	pr_info("Cache is connected to Proxy through fd %d\n", proxy_to_cache_fd);

	local_req_fd = setup_UNIX_server_socket(local_cache_path);
	if (local_req_fd < 0) {
		pr_perror("Unable to open cache to proxy UNIX socket");
		return -1; // TODO - should close other sockets.

	}

	if (background) {
		if (daemon(1, 0) == -1) {
			pr_perror("Can't run service server in the background");
			return -1;
		}
	}

	accept_image_connections();
	pr_info("Finished image cache.");
	return 0;
}
