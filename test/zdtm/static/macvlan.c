#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <linux/limits.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/if.h>
#include "zdtmtst.h"

const char *test_doc	= "check that macvlan interfaces are c/r'd correctly";
const char *test_author	= "Tycho Andersen <tycho.andersen@canonical.com>";

#define BRIDGE_NAME "zdtmbr0"
#define IF_NAME "zdtmmvlan0"

int add_macvlan(void)
{
	/* create a bridge to attach a macvlan interface to */
	if (system("ip link add " BRIDGE_NAME " type bridge")) {
		pr_err("creating bridge");
		return -1;
	}

	if (system("ip addr add 10.0.55.55/32 dev " BRIDGE_NAME)) {
		pr_err("adding bridge addr");
		return -1;
	}

	if (system("ip link set " BRIDGE_NAME " up")) {
		pr_err("setting bridge up");
		return -1;
	}

	if (system("ip link add " IF_NAME " link " BRIDGE_NAME " type macvlan mode bridge")) {
		pr_err("adding macvlan link failed");
		return -1;
	}

	if (system("ip addr add 10.0.55.56/32 dev " IF_NAME)) {
		pr_err("adding bridge addr");
		return -1;
	}


	if (system("ip link set up " IF_NAME)) {
		pr_err("setting macvlan link up");
		return -1;
	}

	return 0;
}

int del_macvlan(void)
{
	system("ip link del " IF_NAME);
	return system("ip link del " BRIDGE_NAME);
}

int main(int argc, char **argv)
{
	int ret = 1;

	test_init(argc, argv);

	if (add_macvlan() < 0)
		return ret;

	if (system("ip addr list dev " IF_NAME " | grep inet > macvlan.dump.test")) {
		fail("can't save net config");
		goto out;
	}

	test_daemon();
	test_waitsig();

	if (system("ip addr list dev " IF_NAME " | grep inet > macvlan.rst.test")) {
		fail("can't get net config");
		goto out;
	}

	if (system("diff macvlan.rst.test macvlan.dump.test")) {
		fail("Net config differs after restore");
		goto out;
	}

	pass();
	ret = 0;

out:
	del_macvlan();
	return ret;
}
