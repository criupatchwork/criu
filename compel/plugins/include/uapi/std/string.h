#ifndef COMPEL_PLUGIN_STD_STRING_H__
#define COMPEL_PLUGIN_STD_STRING_H__

extern unsigned long std_strtoul(const char *nptr, char **endptr, int base);
extern void *std_memcpy(void *to, const void *from, unsigned int n);
extern void std_memset(void *s, int c, unsigned int n);
extern int std_memcmp(const void *cs, const void *ct, unsigned int count);
extern int std_strcmp(const char *cs, const char *ct);
extern int std_strncmp(const char *cs, const char *ct, unsigned int count);

#endif /* COMPEL_PLUGIN_STD_STRING_H__ */
