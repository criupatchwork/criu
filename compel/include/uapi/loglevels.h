#ifndef UAPI_COMPEL_LOGLEVELS_H__
#define UAPI_COMPEL_LOGLEVELS_H__

#define LOG_UNSET		(-1)
#define LOG_MSG			(0) /* Print message regardless of log level */
#define LOG_ERROR		(1) /* Errors only, when we're in trouble */
#define LOG_WARN		(2) /* Warnings, dazen and confused but trying to continue */
#define LOG_INFO		(3) /* Informative, everything is fine */
#define LOG_DEBUG		(4) /* Debug only */

#define DEFAULT_LOGLEVEL	LOG_WARN

#endif /* UAPI_COMPEL_LOGLEVELS_H__ */
