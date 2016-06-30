#ifndef ZDTM_RANDRANGE_H_
#define ZDTM_RANDRANGE_H_

#define INT_MAX ((int)(~0U>>1))

struct rand_range {
	int min;
	int max;
};

extern int irand_range(struct rand_range *rr);

#endif /* ZDTM_RANDRANGE_H_ */
