#include <stdlib.h>
#include <string.h>

#include "uapi/compel.h"

int libcompel_pack_argv(void *blob, size_t blob_size,
			int argc, char **argv,
			void **arg_p, size_t *arg_size)
{
	unsigned long *argv_packed;
	size_t total_len;
	int i, *argc_packed;
	char *args_mem;

	total_len = sizeof(int);
	total_len += sizeof(unsigned long) + blob_size + 1;
	for (i = 0; i < argc; i++)
		total_len += sizeof(unsigned long) + strlen(argv[i]) + 1;

	argc_packed = malloc(total_len);
	if (!argc_packed)
		return -ENOMEM;

	*argc_packed = argc + 1;
	argv_packed = (unsigned long *)(argc_packed + 1);
	args_mem = (char *)(argv_packed + argc + 1);
	argv_packed[0] = (void *)args_mem - (void *)argc_packed;
	memcpy(args_mem, blob, blob_size);
	args_mem += blob_size + 1;
	for (i = 0; i < argc; i++) {
		argv_packed[i + 1] = (void *)args_mem - (void *)argc_packed;
		args_mem = stpcpy(args_mem, argv[i]) + 1;
	}

	*arg_p = argc_packed;
	*arg_size = total_len;

	return 0;
}
