#ifndef EXAMPLE_1_LOG_H__
#define EXAMPLE_1_LOG_H__

#include <compel/loglevels.h>

extern unsigned int log_get_loglevel(void);
extern void __print_on_level(unsigned int loglevel, const char *format, va_list params);
extern void print_on_level(unsigned int loglevel, const char *format, ...);

#ifndef LOG_PREFIX
# define LOG_PREFIX
#endif

#define pr_msg(fmt, ...)						\
	print_on_level(LOG_MSG,						\
		       fmt, ##__VA_ARGS__)

#define pr_info(fmt, ...)						\
	print_on_level(LOG_INFO,					\
		       LOG_PREFIX fmt, ##__VA_ARGS__)

#define pr_err(fmt, ...)						\
	print_on_level(LOG_ERROR,					\
		       "Error (%s:%d): " LOG_PREFIX fmt,		\
		       __FILE__, __LINE__, ##__VA_ARGS__)

#define pr_err_once(fmt, ...)						\
	print_once(LOG_ERROR, fmt, ##__VA_ARGS__)

#define pr_warn(fmt, ...)						\
	print_on_level(LOG_WARN,					\
		       "Warn  (%s:%d): " LOG_PREFIX fmt,		\
		       __FILE__, __LINE__, ##__VA_ARGS__)

#define pr_warn_once(fmt, ...)						\
	print_once(LOG_WARN, fmt, ##__VA_ARGS__)

#define pr_debug(fmt, ...)						\
	print_on_level(LOG_DEBUG,					\
		       LOG_PREFIX fmt, ##__VA_ARGS__)

#define pr_perror(fmt, ...)						\
	pr_err(fmt ": %s\n", ##__VA_ARGS__, strerror(errno))

#endif /* EXAMPLE_1_LOG_H__ */
