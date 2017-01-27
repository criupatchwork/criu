#include <sys/types.h>
#include <stdbool.h>
#include <stdarg.h>

#include "uapi/std/syscall.h"
#include "uapi/std/print.h"

static const char conv_tab[] = "0123456789abcdefghijklmnopqrstuvwxyz";

void __std_putc(int fd, char c)
{
	sys_write(fd, &c, 1);
}

void __std_puts(int fd, const char *s)
{
	for (; *s; s++)
		__std_putc(fd, *s);
}

static size_t __std_vprint_long_hex(char *buf, size_t blen, unsigned long num, char **ps)
{
	char *s = &buf[blen - 2];

	buf[blen - 1] = '\0';

	if (num == 0) {
		*s = '0', s--;
		goto done;
	}

	while (num > 0) {
		*s = conv_tab[num % 16], s--;
		num /= 16;
	}

done:
	s++;
	*ps = s;
	return blen - (s - buf);
}

static size_t __std_vprint_long(char *buf, size_t blen, long num, char **ps)
{
	char *s = &buf[blen - 2];
	int neg = 0;

	buf[blen - 1] = '\0';

	if (num < 0) {
		neg = 1;
		num = -num;
	} else if (num == 0) {
		*s = '0';
		s--;
		goto done;
	}

	while (num > 0) {
		*s = (num % 10) + '0';
		s--;
		num /= 10;
	}

	if (neg) {
		*s = '-';
		s--;
	}
done:
	s++;
	*ps = s;
	return blen - (s - buf);
}

void __std_printk(int fd, const char *format, va_list args)
{
	const char *s = format;

	for (; *s != '\0'; s++) {
		char buf[32], *t;
		int along = 0;

		if (*s != '%') {
			__std_putc(fd, *s);
			continue;
		}

		s++;
		if (*s == 'l') {
			along = 1;
			s++;
			if (*s == 'l')
				s++;
		}

		switch (*s) {
		case 's':
			__std_puts(fd, va_arg(args, char *));
			break;
		case 'd':
			__std_vprint_long(buf, sizeof(buf),
					  along ?
					  va_arg(args, long) :
					  (long)va_arg(args, int),
					  &t);
			__std_puts(fd, t);
			break;
		case 'x':
			__std_vprint_long_hex(buf, sizeof(buf),
					      along ?
					      va_arg(args, long) :
					      (long)va_arg(args, int),
					      &t);
			__std_puts(fd, t);
			break;
		}
	}
}

void __std_printf(int fd, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	__std_printk(fd, format, args);
	va_end(args);
}
