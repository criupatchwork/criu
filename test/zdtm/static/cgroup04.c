
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <limits.h>
#include "zdtmtst.h"

const char *test_doc	= "Check that some cgroups properties in kernel controllers are preserved";
const char *test_author	= "Tycho Andersen <tycho.andersen@canonical.com>";

char *dirname;
TEST_OPTION(dirname, string, "cgroup directory name", 1);
static const char *cgname = "zdtmtst";

int write_value(const char *path, const char *value)
{
	int fd, l;

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		pr_perror("open %s", path);
		return -1;
	}

	l = write(fd, value, strlen(value));
	close(fd);
	if (l < 0) {
		pr_perror("failed to write %s to %s", value, path);
		return -1;
	}

	return 0;
}

int mount_and_add(const char *controller, const char *path, const char *prop, const char *value)
{
	char aux[1024], paux[1024], subdir[1024];

	if (mkdir(dirname, 0700) < 0 && errno != EEXIST) {
		pr_perror("Can't make dir");
		return -1;
	}

	sprintf(subdir, "%s/%s", dirname, controller);
	if (mkdir(subdir, 0700) < 0) {
		pr_perror("Can't make dir");
		return -1;
	}

	if (mount("none", subdir, "cgroup", 0, controller)) {
		pr_perror("Can't mount cgroups");
		goto err_rd;
	}

	sprintf(paux, "%s/%s", subdir, path);
	mkdir(paux, 0600);

	sprintf(paux, "%s/%s/%s", subdir, path, prop);
	if (write_value(paux, value) < 0)
		goto err_rs;

	sprintf(aux, "%d", getpid());
	sprintf(paux, "%s/%s/tasks", subdir, path);
	if (write_value(paux, aux) < 0)
		goto err_rs;

	return 0;
err_rs:
	umount(dirname);
err_rd:
	rmdir(dirname);
	return -1;
}

bool checkval(char *path, char *val)
{
	FILE *f;
	char buf[64];

	f = fopen(path, "r");
	if (!f) {
		pr_perror("fopen %s", path);
		return false;
	}

	fgets(buf, sizeof(buf), f);
	fclose(f);

	if (strcmp(val, buf)) {
		pr_err("got %s expected %s\n", buf, val);
		return false;
	}

	return true;
}

int main(int argc, char **argv)
{
	int ret = -1;
	char path[PATH_MAX];

	test_init(argc, argv);

	if (mount_and_add("devices", cgname, "devices.deny", "a") < 0)
		goto out;

	/* need to allow /dev/null for restore */
	sprintf(path, "%s/devices/%s/devices.allow", dirname, cgname);
	if (write_value(path, "c 1:3 rwm") < 0)
		goto out;

	if (mount_and_add("memory", cgname, "memory.limit_in_bytes", "268435456") < 0)
		goto out;

	test_daemon();
	test_waitsig();

	sprintf(path, "%s/devices/%s/devices.list", dirname, cgname);
	if (!checkval(path, "c 1:3 rwm\n")) {
		fail();
		goto out;
	}

	sprintf(path, "%s/memory/%s/memory.limit_in_bytes", dirname, cgname);
	if (!checkval(path, "268435456\n")) {
		fail();
		goto out;
	}

	pass();
	ret = 0;
out:
	sprintf(path, "%s/devices/%s", dirname, cgname);
	rmdir(path);
	sprintf(path, "%s/devices", dirname);
	umount(path);

	sprintf(path, "%s/memory/%s", dirname, cgname);
	rmdir(path);
	sprintf(path, "%s/memory", dirname);
	umount(path);

	return ret;
}
