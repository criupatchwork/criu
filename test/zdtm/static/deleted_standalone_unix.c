#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that deleted unix sockets are restored correctly";
const char *test_author	= "Tycho Andersen <tycho.andersen@canonical.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

static int fill_sock_name(struct sockaddr_un *name, const char *filename)
{
	char *cwd;

	cwd = get_current_dir_name();
	if (strlen(filename) + strlen(cwd) + 1 >= sizeof(name->sun_path))
		return -1;

	name->sun_family = AF_LOCAL;
	sprintf(name->sun_path, "%s/%s", cwd, filename);
	return 0;
}

int main(int argc, char **argv)
{
	struct sockaddr_un addr;
	int sk, ret = 1;
	struct stat sb;

	test_init(argc, argv);

	sk = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sk < 0) {
		fail("socket");
		return 1;
	}

	if (fill_sock_name(&addr, filename) < 0) {
		pr_err("filename \"%s\" is too long", filename);
		goto out;
	}

	if (bind(sk, &addr, sizeof(addr))) {
		fail("bind");
		goto out;
	}

	if (listen(sk, 1)) {
		fail("listen");
		goto out;
	}

	if (unlink(addr.sun_path) < 0) {
		fail("unlink");
		goto out;
	}

	test_daemon();
	test_waitsig();

	if (getsockopt(sk, 0, 0, NULL, 0) && errno != EOPNOTSUPP) {
		fail("socket didn't survive restore");
		goto out;
	}

	if (stat(addr.sun_path, &sb) == 0 || errno != ENOENT) {
		fail("%s exists after restore\n", addr.sun_path);
		goto out;
	}

	pass();
	ret = 0;
out:
	close(sk);
	return ret;
}
