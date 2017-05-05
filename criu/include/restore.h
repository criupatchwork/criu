#ifndef __CR_INC_RESTORE_H__
#define __CR_INC_RESTORE_H__
#include "types.h"
#include "asm/restore.h"

extern int criu_signals_setup(void (*handler)(int, siginfo_t *, void *));

#endif
