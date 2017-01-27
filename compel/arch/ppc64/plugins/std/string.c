void *std_memcpy(void *to, const void *from, unsigned int n)
{
	char *tmp = to;
	const char *s = from;

	while (n--)
		*tmp++ = *s++;
	return to;
}

void std_memset(void *s, int c, unsigned int n)
{
	char *xs = s;

	while (count--)
		*xs++ = c;
	return s;
}
