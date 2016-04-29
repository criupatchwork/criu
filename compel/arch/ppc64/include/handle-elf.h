#ifndef __COMPEL_HANDLE_ELF_H__
#define __COMPEL_HANDLE_ELF_H__

#include "uapi/elf32-types.h"

#define ELF_PPC64
#define __handle_elf	handle_elf_ppc64

extern int handle_elf_ppc64(void *mem, size_t size);

#endif /* __COMPEL_HANDLE_ELF_H__ */
