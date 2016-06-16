#ifndef __CR_SK_QUEUE_H__
#define __CR_SK_QUEUE_H__

#include "list.h"
#include "images/sk-packet.pb-c.h"

#define SK_NONAME_SENDER	(~0ULL)

struct sk_packet {
	struct list_head	list;
	SkPacketEntry		*entry;
	off_t			img_off;
};

extern struct list_head packets_list;

extern struct collect_image_info sk_queues_cinfo;
extern int dump_sk_queue(int sock_fd, int sock_id, u64 (*get_sender)(const char *, int));
extern int restore_sk_queue(int fd, unsigned int peer_id);

#endif /* __CR_SK_QUEUE_H__ */
