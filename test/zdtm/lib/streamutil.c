#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "zdtmtst.h"

int set_nonblock(int fd, int on)
{
	int flag;

	flag = fcntl(fd, F_GETFL, 0);

	if (flag < 0)
		return flag;

	if (on)
		flag |= O_NONBLOCK;
	else
		flag &= ~O_NONBLOCK;

	return fcntl(fd, F_SETFL, flag);
}

int pipe_in2out(int infd, int outfd, uint8_t *buffer, int length)
{
	uint8_t *buf;
	int rlen, wlen;

	while (1) {
		rlen = read(infd, buffer, length);
		if (rlen <= 0)
			return rlen;

		/* don't go reading until we're done with writing */
		for (buf = buffer; rlen > 0; buf += wlen, rlen -= wlen) {
			wlen = write(outfd, buf, rlen);
			if (wlen < 0)
				return wlen;
		}
	}
}

int read_data(int fd, unsigned char *buf, int size)
{
	int cur = 0;
	int ret;
	while (cur != size) {
		ret = read(fd, buf + cur, size - cur);
		if (ret <= 0)
			return -1;
		cur += ret;
	}

	return 0;
}

int write_data(int fd, const unsigned char *buf, int size)
{
	int cur = 0;
	int ret;

	while (cur != size) {
		ret = write(fd, buf + cur, size - cur);
		if (ret <= 0)
			return -1;
		cur += ret;
	}

	return 0;
}

int fill_sock_buf(int fd)
{
	int flags;
	int size;
	int ret;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		pr_err("Can't get flags");
		return -1;
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		pr_err("Can't set flags");
		return -1;
	}

	size = 0;
	while (1) {
		char zdtm[] = "zdtm test packet";
		ret = write(fd, zdtm, sizeof(zdtm));
		if (ret == -1) {
			if (errno == EAGAIN)
				break;
			pr_err("write");
			return -1;
		}
		size += ret;
	}

	if (fcntl(fd, F_SETFL, flags) == -1) {
		pr_err("Can't set flags");
		return -1;
	}

	test_msg("snd_size = %d\n", size);

	return size;
}

#define BUF_SIZE 4096

int clean_sk_buf(int fd, int limit)
{
	int size, ret;
	char buf[BUF_SIZE];

	size = 0;
	while (1) {
		ret = read(fd, buf, sizeof(buf));
		if (ret == -1) {
			pr_err("read");
			return -11;
		}

		if (ret == 0)
			break;

		size += ret;

		if (limit && size >= limit)
			break;

	}

	test_msg("rcv_size = %d\n", size);

	return size;
}
