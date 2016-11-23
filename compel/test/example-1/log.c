#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "log.h"

static unsigned int current_loglevel = LOG_DEBUG;

unsigned int log_get_loglevel(void)
{
	return current_loglevel;
}

void __print_on_level(unsigned int loglevel, const char *format, va_list params)
{
	int size, ret, off = 0;
	int __errno = errno;
	char buffer[1024];

	if (loglevel != LOG_MSG && loglevel > current_loglevel)
		return;

	size = vsnprintf(buffer, sizeof(buffer), format, params);

	while (off < size) {
		ret = write(STDOUT_FILENO, buffer + off, size - off);
		if (ret <= 0)
			break;
		off += ret;
	}
	errno =  __errno;
}

void print_on_level(unsigned int loglevel, const char *format, ...)
{
	va_list params;

	va_start(params, format);
	__print_on_level(loglevel, format, params);
	va_end(params);
}
