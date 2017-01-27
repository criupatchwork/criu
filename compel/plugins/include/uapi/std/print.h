#ifndef COMPEL_PLUGIN_STD_PRINT_H__
#define COMPEL_PLUGIN_STD_PRINT_H__

#include <sys/types.h>
#include <stdbool.h>
#include <stdarg.h>

/* Standard file descriptors.  */
#define	STDIN_FILENO	0	/* Standard input.  */
#define	STDOUT_FILENO	1	/* Standard output.  */
#define	STDERR_FILENO	2	/* Standard error output.  */


extern void __std_putc(int fd, char c);
extern void __std_puts(int fd, const char *s);
extern void __std_printk(int fd, const char *format, va_list args);
extern void __std_printf(int fd, const char *format, ...);

#define std_printf(fmt, ...)	__std_printf(STDOUT_FILENO, fmt, ##__VA_ARGS__)
#define std_puts(s)		__std_puts(STDOUT_FILENO, s)
#define std_putchar(c)		__std_putc(STDOUT_FILENO, c)

#endif /* COMPEL_PLUGIN_STD_PRINT_H__ */
