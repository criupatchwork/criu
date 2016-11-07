#ifndef __COMPEL_INFECT_RPC_H__
#define __COMPEL_INFECT_RPC_H__
extern int compel_rpc_sync(unsigned int cmd, struct parasite_ctl *ctl);
extern int compel_rpc_call(unsigned int cmd, struct parasite_ctl *ctl);
extern int compel_rpc_call_sync(unsigned int cmd, struct parasite_ctl *ctl);
extern int compel_rpc_sock(struct parasite_ctl *ctl);

struct ctl_msg {
	u32	cmd;			/* command itself */
	u32	ack;			/* ack on command */
	s32	err;			/* error code on reply */
};

#define ctl_msg_cmd(_cmd)		\
	(struct ctl_msg){.cmd = _cmd, }

#define ctl_msg_ack(_cmd, _err)	\
	(struct ctl_msg){.cmd = _cmd, .ack = _cmd, .err = _err, }

#endif
