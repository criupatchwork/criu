#include <string.h>
#include <stdio.h>

#include "mount.h"
#include "path.h"
#include "bug.h"

char *cut_root_for_bind(char *target_root, char *source_root)
{
	int tok = 0;
	char *path = NULL;
	/*
	 * Cut common part of root.
	 * For non-root binds the source is always "/" (checked)
	 * so this will result in this slash removal only.
	 */
	while (target_root[tok] == source_root[tok]) {
		tok++;
		if (source_root[tok] == '\0') {
			path = target_root + tok;
			goto out;
		}
		if (target_root[tok] == '\0') {
			path = source_root + tok;
			goto out;
		}
	}

	return NULL;
out:
	BUG_ON(path == NULL);
	if (path[0] == '/')
		path++;

	return path;
}

char *mnt_get_sibling_path(struct mount_info *m,
			   struct mount_info *p, char *buf, int len)
{
	struct mount_info *pa = m->parent;
	char *rpath, *cut_root, *path = buf;
	int off = 0;

	if (pa == NULL)
		return NULL;

	rpath = m->mountpoint + strlen(pa->mountpoint);
	if (rpath[0] == '/')
		rpath++;

	/*
	 * Get a path to a sibling of "m" with parent "p",
	 * return NULL is p can't have a sibling of m.
	 *
	 * Here are two cases:
	 * When a parent of "m" has longer root than "p":
	 * /    pm->root            / rpath
	 *               | cut_root |
	 * /    p->root  /
	 * In this case, a sibling path is a sum of p->mountpoint,
	 * cut_root and rpath.
	 *
	 * When a parent of m has shorter root than "p":
	 * /    pm->root /            rpath
	 *               | cut_root |
	 * /    p->root             / rpath +strlen(cut_root)
	 * In this case, a sibling path is a sum of p->mountpoint and
	 * rpath - strlen(cut_root).
	 */

	cut_root = cut_root_for_bind(pa->root, p->root);
	if (cut_root == NULL)
		return NULL;
	if (p->mountpoint[1] != 0) /* not "/" */
		off = snprintf(path, len, "%s", p->mountpoint);
	if (path[off - 1] == '/') /* p->mountpoint = "./" */
		off--;
	len -= off;
	path += off;

	if (strlen(pa->root) > strlen(p->root)) {
		off = snprintf(path, len, "/%s", cut_root);
		len -= off;
		path += off;
	} else {
		int len = strlen(cut_root);
		if (strncmp(rpath, cut_root, len))
			return NULL;
		rpath += strlen(cut_root);
		if (len > 0 && (rpath[0] && rpath[0] != '/'))
			return NULL;
	}
	if (rpath[0] == '/')
		rpath++;

	off = snprintf(path, len, "/%s", rpath);
	len -= off;
	path += off;

	return buf;
}

#ifdef CONFIG_SELF_TEST
__attribute__ ((__constructor__))
static void mnt_get_sibling_path_test()
{
	char path[PATH_MAX];
	struct mount_info m = {}, pm = {}, t = {};

	m.parent = &pm;
#define MNT_SIBLING_TEST(proot, pmnt, mnt, troot, tmnt, result)	\
{								\
	char *res;						\
	pm.root = proot;					\
	pm.mountpoint = pmnt;					\
	m.mountpoint = mnt;					\
	t.root = troot;						\
	t.mountpoint = tmnt;					\
								\
	res = mount_sibling(&m, &t, path, sizeof(path));	\
	if (res && result)					\
		BUG_ON(strcmp(res, result));			\
	else							\
		BUG_ON(result || res);				\
}

	MNT_SIBLING_TEST("/",    "/xxx", "/xxx/yyy/zzz",  "/",	     "/aaa", "/aaa/yyy/zzz");
	MNT_SIBLING_TEST("/yyy", "/xxx", "/xxx/yyy/zzz", "/yyy",     "/aaa", "/aaa/yyy/zzz");
	MNT_SIBLING_TEST("/",    "/xxx", "/xxx/yyy/zzz", "/yyy",     "/aaa", "/aaa/zzz");
	MNT_SIBLING_TEST("/aaa", "/xxx", "/xxx/yyy/zzz", "/aaa/yyy", "/aaa", "/aaa/zzz");
	MNT_SIBLING_TEST("/yyy", "/xxx", "/xxx/yyy/zzz", "/",        "/aaa", "/aaa/yyy/yyy/zzz");
	MNT_SIBLING_TEST("/",    "/",    "/",            "/",        "/",    "/");
	MNT_SIBLING_TEST("/aaa", "/bbb", "/bbb/caa",     "/",        "/",    "/aaa/caa");
	MNT_SIBLING_TEST("/aaa", "./bbb", "./bbb/caa",   "/",        "./",   "./aaa/caa");
	MNT_SIBLING_TEST("/aaa", "/",    "/",            "/bbb",     "/",    NULL);
#undef MNT_SIBLING_TEST

}
#endif
