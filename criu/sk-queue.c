#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sendfile.h>

#include "asm/types.h"
#include "list.h"
#include "imgset.h"
#include "image.h"
#include "servicefd.h"
#include "cr_options.h"
#include "util.h"
#include "util-pie.h"
#include "sockets.h"

#include "sk-queue.h"

#include "protobuf.h"
#include "images/sk-packet.pb-c.h"

struct sk_packet {
	struct list_head	list;
	SkPacketEntry		*entry;
	off_t			img_off;
};

static LIST_HEAD(packets_list);

static int collect_one_packet(void *obj, ProtobufCMessage *msg, struct cr_img *img)
{
	struct sk_packet *pkt = obj;

	pkt->entry = pb_msg(msg, SkPacketEntry);
	pkt->img_off = lseek(img_raw_fd(img), 0, SEEK_CUR);
	/*
	 * NOTE: packet must be added to the tail. Otherwise sequence
	 * will be broken.
	 */
	list_add_tail(&pkt->list, &packets_list);
	if (lseek(img_raw_fd(img), pkt->entry->length, SEEK_CUR) < 0) {
		pr_perror("Unable to change an image offset");
		return -1;
	}

	return 0;
}

struct collect_image_info sk_queues_cinfo = {
	.fd_type = CR_FD_SK_QUEUES,
	.pb_type = PB_SK_QUEUES,
	.priv_size = sizeof(struct sk_packet),
	.collect = collect_one_packet,
};

/* Currently known the longest possible sender name thru all socket types */
#define MAX_MSG_NAME_LEN	(sizeof (struct sockaddr_un))

int dump_sk_queue(int sock_fd, int sock_id, u64 (*get_sender)(const char *, int))
{
	int ret, size, orig_peek_off;
	void *data, *mem;
	socklen_t tmp;
	u64 next;

	/*
	 * Save original peek offset.
	 */
	tmp = sizeof(orig_peek_off);
	orig_peek_off = 0;
	ret = getsockopt(sock_fd, SOL_SOCKET, SO_PEEK_OFF, &orig_peek_off, &tmp);
	if (ret < 0) {
		pr_perror("getsockopt failed");
		return ret;
	}
	/*
	 * Discover max DGRAM size
	 */
	tmp = sizeof(size);
	size = 0;
	ret = getsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &size, &tmp);
	if (ret < 0) {
		pr_perror("getsockopt failed");
		return ret;
	}

	if (get_sender)
		size += MAX_MSG_NAME_LEN;

	/* Note: 32 bytes will be used by kernel for protocol header. */
	size -= 32;

	/*
	 * Allocate data for a stream.
	 */
	mem = data = xmalloc(size);
	if (!mem)
		return -1;

	if (get_sender)
		data += MAX_MSG_NAME_LEN;

	/*
	 * Enable peek offset incrementation.
	 */
	ret = setsockopt(sock_fd, SOL_SOCKET, SO_PEEK_OFF, &ret, sizeof(int));
	if (ret < 0) {
		pr_perror("setsockopt fail");
		goto err_brk;
	}

	while (1) {
		SkPacketEntry pe = SK_PACKET_ENTRY__INIT;
		struct iovec iov = {
			.iov_base	= data,
			.iov_len	= size,
		};
		struct msghdr msg = {
			.msg_iov	= &iov,
			.msg_iovlen	= 1,
		};

		if (get_sender) {
			msg.msg_name	= mem;
			msg.msg_namelen	= MAX_MSG_NAME_LEN;
		}

		pe.id_for = sock_id;
		ret = pe.length = recvmsg(sock_fd, &msg, MSG_DONTWAIT | MSG_PEEK);
		if (!ret)
			/*
			 * It means, that peer has performed an
			 * orderly shutdown, so we're done.
			 */
			break;
		else if (ret < 0) {
			if (errno == EAGAIN)
				break; /* we're done */
			pr_perror("recvmsg fail: error");
			goto err_set_sock;
		}
		if (msg.msg_flags & MSG_TRUNC) {
			/*
			 * DGRAM truncated. This should not happen. But we have
			 * to check...
			 */
			pr_err("sys_recvmsg failed: truncated\n");
			ret = -E2BIG;
			goto err_set_sock;
		}

		if (get_sender) {
			next = get_sender(msg.msg_name, msg.msg_namelen);
			if (!next) {
				pr_err("Can't find sender for skb\n");
				ret = -ENODEV;
				goto err_set_sock;
			} else if (next != SK_NONAME_SENDER) {
				pe.has_sender_ino = true;
				pe.sender_ino = next;
			}
		}

		ret = pb_write_one(img_from_set(glob_imgset, CR_FD_SK_QUEUES), &pe, PB_SK_QUEUES);
		if (ret < 0) {
			ret = -EIO;
			goto err_set_sock;
		}

		ret = write_img_buf(img_from_set(glob_imgset, CR_FD_SK_QUEUES), data, pe.length);
		if (ret < 0) {
			ret = -EIO;
			goto err_set_sock;
		}
	}
	ret = 0;

err_set_sock:
	/*
	 * Restore original peek offset.
	 */
	if (setsockopt(sock_fd, SOL_SOCKET, SO_PEEK_OFF, &orig_peek_off, sizeof(int))) {
		pr_perror("setsockopt failed on restore");
		ret = -1;
	}
err_brk:
	xfree(mem);
	return ret;
}

int restore_sk_queue(int fd, unsigned int peer_id)
{
	struct sk_packet *pkt, *tmp;
	int ret;
	struct cr_img *img;

	pr_info("Trying to restore recv queue for %u\n", peer_id);

	if (restore_prepare_socket(fd))
		return -1;

	img = open_image(CR_FD_SK_QUEUES, O_RSTR);
	if (!img)
		return -1;

	list_for_each_entry_safe(pkt, tmp, &packets_list, list) {
		SkPacketEntry *entry = pkt->entry;
		char *buf;

		if (entry->id_for != peer_id)
			continue;

		pr_info("\tRestoring %d-bytes skb for %u\n",
			(unsigned int)entry->length, peer_id);

		/*
		 * Don't try to use sendfile here, because it use sendpage() and
		 * all data are split on pages and a new skb is allocated for
		 * each page. It creates a big overhead on SNDBUF.
		 * sendfile() isn't suitable for DGRAM sockets, because message
		 * boundaries messages should be saved.
		 */

		buf = xmalloc(entry->length);
		if (buf ==NULL)
			goto err;

		if (lseek(img_raw_fd(img), pkt->img_off, SEEK_SET) == -1) {
			pr_perror("lseek() failed");
			xfree(buf);
			goto err;
		}
		if (read_img_buf(img, buf, entry->length) != 1) {
			xfree(buf);
			goto err;
		}

		ret = write(fd, buf, entry->length);
		xfree(buf);
		if (ret < 0) {
			pr_perror("Failed to send packet");
			goto err;
		}
		if (ret != entry->length) {
			pr_err("Restored skb trimmed to %d/%d\n",
			       ret, (unsigned int)entry->length);
			goto err;
		}
		list_del(&pkt->list);
		sk_packet_entry__free_unpacked(entry, NULL);
		xfree(pkt);
	}

	close_image(img);
	return 0;
err:
	close_image(img);
	return -1;
}
