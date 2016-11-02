#ifndef __CR_ASM_PAGE_H__
#define __CR_ASM_PAGE_H__

#include "config.h"

#ifndef PAGE_MASK
# define PAGE_MASK	(~(PAGE_SIZE - 1))
#endif

#define PAGE_PFN(addr)	((addr) / PAGE_SIZE)
#define page_size()	PAGE_SIZE

#endif /* __CR_ASM_PAGE_H__ */
