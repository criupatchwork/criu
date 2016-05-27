#include <pthread.h>

void *dirty_logger_pthread(void *arg)
{
	pthread_exit(NULL);
}
