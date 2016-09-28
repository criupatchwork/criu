#ifndef UAPI_COMPEL_H__
#define UAPI_COMPEL_H__

#include <errno.h>

#define COMPEL_TYPE_INT		(1u << 0)
#define COMPEL_TYPE_LONG	(1u << 1)
#define COMPEL_TYPE_GOTPCREL	(1u << 2)

typedef struct {
	unsigned int	offset;
	unsigned int	type;
	long		addend;
	long		value;
} compel_reloc_t;

extern int libcompel_pack_argv(void *blob, size_t blob_size,
			       int argc, char **argv,
			       void **arg_p, size_t *arg_size);

#endif /* UAPI_COMPEL_H__ */
