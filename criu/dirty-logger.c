#include <pthread.h>

#include "imgset.h"

void img_cleanup(void *arg)
{
       close_image((struct cr_img *)arg);
}

#define CR_DIRTY_LOG "dirty-log.img"

void *dirty_logger_pthread(void *arg)
{
	int *pret = (int *)arg;
	struct cr_img *img;

	img = open_image_at(AT_FDCWD, CR_FD_DIRTY_LOG, O_DUMP);
	if (!img) {
		*pret = -1;
		pthread_exit(NULL);
	}
	pthread_cleanup_push(img_cleanup, (void *)img);

	*pret = 0;
	pthread_cleanup_pop(1);
	pthread_exit(NULL);
}
