#include <stdlib.h>

#include "randrange.h"

/* Generate random integers for sysctls */

static int irand_small_range(struct rand_range *rr) {
	return lrand48() % (rr->max - rr->min + 1) + rr->min;
}

int irand_range(struct rand_range *rr) {
	struct rand_range small;
	int mid, half;

	if (rr->max < rr->min) {
		/* Fixup wrong order */
		int tmp = rr->min;
		rr->min = rr->max;
		rr->max = tmp;
	}
	mid = rr->max / 2 + rr->min / 2;
	half = rr->max / 2 - rr->min / 2;

	if (half < INT_MAX / 2)
		return irand_small_range(rr);

	if (lrand48() % 2) {
		small.min = rr->min;
		small.max = mid;
	} else {
		small.min = mid + 1;
		small.max = rr->max;
	}

	return irand_small_range(&small);
}
