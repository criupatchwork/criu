#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "compiler.h"
#include "cgroup-props.h"
#include "config.h"
#include "xmalloc.h"
#include "string.h"
#include "util.h"
#include "list.h"
#include "log.h"
#include "bug.h"

#ifdef CONFIG_HAS_YAML
# include <yaml.h>
#endif

#undef	LOG_PREFIX
#define LOG_PREFIX "cg-prop: "

/*
 * Predefined properties.
 */
static const char *cpu_props[] = {
	"cpu.shares",
	"cpu.cfs_period_us",
	"cpu.cfs_quota_us",
	"cpu.rt_period_us",
	"cpu.rt_runtime_us",
	"notify_on_release",
};

static const char *memory_props[] = {
	/* limit_in_bytes and memsw.limit_in_bytes must be set in this order */
	"memory.limit_in_bytes",
	"memory.memsw.limit_in_bytes",
	"memory.use_hierarchy",
	"notify_on_release",
};

static const char *cpuset_props[] = {
	/*
	 * cpuset.cpus and cpuset.mems must be set before the process moves
	 * into its cgroup; they are "initialized" below to whatever the root
	 * values are in copy_special_cg_props so as not to cause ENOSPC when
	 * values are restored via this code.
	 */
	"cpuset.cpus",
	"cpuset.mems",
	"cpuset.memory_migrate",
	"cpuset.cpu_exclusive",
	"cpuset.mem_exclusive",
	"cpuset.mem_hardwall",
	"cpuset.memory_spread_page",
	"cpuset.memory_spread_slab",
	"cpuset.sched_load_balance",
	"cpuset.sched_relax_domain_level",
	"notify_on_release",
};

static const char *blkio_props[] = {
	"blkio.weight",
	"notify_on_release",
};

static const char *freezer_props[] = {
	"notify_on_release",
};

static const char *____criu_global_props____[] = {
	"cgroup.clone_children",
	"notify_on_release",
	"cgroup.procs",
	"tasks",
};

cgp_t cgp_global = {
	.name		= "____criu_global_props____",
	.nr_props	= ARRAY_SIZE(____criu_global_props____),
	.props		= ____criu_global_props____,
};

typedef struct {
	struct list_head	list;
	cgp_t			cgp;
} cgp_list_entry_t;

static cgp_list_entry_t cgp_predefined[5];

static struct list_head cgp_predefined_list = {
	.next = &cgp_predefined[0].list,
	.prev = &cgp_predefined[4].list,
};

static cgp_list_entry_t cgp_predefined[5] = {
	{
		.list.next	= &cgp_predefined[1].list,
		.list.prev	= &cgp_predefined_list,
		.cgp		= {
			.name		= "cpu",
			.nr_props	= ARRAY_SIZE(cpu_props),
			.props		= cpu_props,
		},
	}, {
		.list.next	= &cgp_predefined[2].list,
		.list.prev	= &cgp_predefined[1].list,
		.cgp		= {
			.name		= "memory",
			.nr_props	= ARRAY_SIZE(memory_props),
			.props		= memory_props,
		},
	}, {
		.list.next	= &cgp_predefined[3].list,
		.list.prev	= &cgp_predefined[2].list,
		.cgp		= {
			.name		= "cpuset",
			.nr_props	= ARRAY_SIZE(cpuset_props),
			.props		= cpuset_props,
		},
	}, {
		.list.next	= &cgp_predefined[4].list,
		.list.prev	= &cgp_predefined[3].list,
		.cgp		= {
			.name		= "blkio",
			.nr_props	= ARRAY_SIZE(blkio_props),
			.props		= blkio_props,
		},
	}, {
		.list.next	= &cgp_predefined_list,
		.list.prev	= &cgp_predefined[4].list,
		.cgp		= {
			.name		= "freezer",
			.nr_props	= ARRAY_SIZE(freezer_props),
			.props		= freezer_props,
		},
	},
};

static LIST_HEAD(cgp_list);

static void cgp_free(cgp_list_entry_t *p)
{
	size_t i;

	if (p) {
		for (i = 0; i < p->cgp.nr_props; i++)
			xfree((void *)p->cgp.props[i]);
		xfree((void *)p->cgp.name);
		xfree((void *)p->cgp.props);
		xfree(p);
	}
}

static cgp_list_entry_t *cgp_get_predefined(const char *name)
{
	cgp_list_entry_t *p;

	list_for_each_entry(p, &cgp_predefined_list, list) {
		if (!strcmp(p->cgp.name, name))
			return p;
	}

	return NULL;
}

static char *skip_spaces(char **stream, size_t *len)
{
	if (stream && *len) {
		char *p = *stream;

		while (p && *len && isspace(*p))
			p++, (*len)--;
		if (p != *stream)
			*stream = p;
		return p;
	}

	return NULL;
}

static char *eat_symbol(char **stream, size_t *len, char sym)
{
	char *p = skip_spaces(stream, len);

	if (!p || *p != sym || !*len)
		return NULL;
	(*stream) = p + 1;
	(*len)--;
	return p;
}

static char *get_quoted(char **stream, size_t *len)
{
	char *p = skip_spaces(stream, len);
	char *from = p + 1;
	char *dst;

	if (!p || *p != '\"')
		return NULL;

	for (p = from, (*len)--; (*len); p++) {
		if (*p == '\"') {
			if (p == from)
				break;
			dst = xmalloc(p - from + 1);
			if (!dst)
				break;

			memcpy(dst, from, p - from);
			dst[p - from] = '\0';

			(*stream) = p + 1;
			(*len)--;

			return dst;
		}
	}

	return NULL;
}

static int cgp_parse_stream(char *stream, size_t len)
{
	cgp_list_entry_t *cgp_entry;
	int ret = 0;
	char *p;

	/*
	 * We expect the following format here
	 * (very simplified YAML!)
	 *
	 *  "cpu": ["cpu.shares", "cpu.cfs_period_us"]
	 *  "memory": ["memory.limit_in_bytes", "memory.memsw.limit_in_bytes"]
	 *
	 *  and etc.
	 */

	while (len) {
		/*
		 * Controller name.
		 */
		p = get_quoted(&stream, &len);
		if (!p)
			break;

		pr_debug("Parsing controller %s\n", p);

		cgp_entry = xzalloc(sizeof(*cgp_entry));
		if (cgp_entry) {
			INIT_LIST_HEAD(&cgp_entry->list);
			cgp_entry->cgp.name = p;
		} else {
			pr_err("Can't allocate memory for controller %s\n", p);
			xfree(p);
			return -ENOMEM;
		}

		p = eat_symbol(&stream, &len, ':');
		if (!p) {
			pr_err("Expected \':\' symbol in controller's %s stream\n",
			       cgp_entry->cgp.name);
			goto err_parse;
		}

		p = eat_symbol(&stream, &len, '[');
		if (!p) {
			pr_err("Expected \'[\' symbol in controller's %s stream\n",
			       cgp_entry->cgp.name);
			goto err_parse;
		}

		while ((p = get_quoted(&stream, &len))) {
			if (!p) {
				pr_err("Expected property name for controller %s\n",
				       cgp_entry->cgp.name);
				goto err_parse;
			}

			if (xrealloc_safe(&cgp_entry->cgp.props,
					  (cgp_entry->cgp.nr_props + 1) * sizeof(char *))) {
				pr_err("Can't allocate property for controller %s\n",
				       cgp_entry->cgp.name);
				return -1;
			}

			cgp_entry->cgp.props[cgp_entry->cgp.nr_props++] = p;
			pr_debug("\tProperty %s\n", p);

			p = eat_symbol(&stream, &len, ',');
			if (!p) {
				if (stream[0] == ']') {
					stream++, len--;
					break;
				}
				pr_err("Expected ']' in controller's %s stream\n",
				       cgp_entry->cgp.name);
				goto err_parse;
			}
		}

		list_add(&cgp_entry->list, &cgp_list);
		cgp_entry = NULL;
	}

	if (!list_empty(&cgp_list)) {
		pr_info("Custom controllers with properties are defined.\n"
			"Zapping compiled in ones.\n");
		INIT_LIST_HEAD(&cgp_predefined_list);
	}

	ret = 0;
out:
	return ret;

err_parse:
	cgp_free(cgp_entry);
	ret = -EINVAL;
	goto out;
}

static int cgp_parse_file(char *path)
{
	void *mem = MAP_FAILED;
	int fd = -1, ret = -1;
	struct stat st;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open file %s\n", path);
		goto err;
	}

	if (fstat(fd, &st)) {
		pr_perror("Can't stat file %s\n", path);
		goto err;
	}

	mem = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FILE, fd, 0);
	if (mem == MAP_FAILED) {
		pr_perror("Can't mmap file %s\n", path);
		goto err;
	}

	if (cgp_parse_stream(mem, st.st_size)) {
		pr_err("Failed to parse file `%s'\n", path);
		goto err;
	}

	ret = 0;
err:
	if (mem != MAP_FAILED)
		munmap(mem, st.st_size);
	close_safe(&fd);
	return ret;
}

int cgp_init(char *stream, size_t len, char *path)
{
	int ret = 0;

	if (stream && len) {
		ret = cgp_parse_stream(stream, len);
		if (ret)
			goto err;
	}

	if (path)
		ret = cgp_parse_file(path);
err:
	return ret;
}

bool cgp_should_skip_controller(const char *name)
{
	cgp_list_entry_t *p;

	list_for_each_entry(p, &cgp_list, list) {
		if (!strcmp(p->cgp.name, name))
			return true;
	}
	return false;
}

const cgp_t *cgp_get_props(const char *name)
{
	cgp_list_entry_t *p;

	p = cgp_get_predefined(name);
	if (p)
		return &p->cgp;

	list_for_each_entry(p, &cgp_list, list) {
		if (!strcmp(p->cgp.name, name))
			return &p->cgp;
	}

	return NULL;
}

void cgp_fini(void)
{
	cgp_list_entry_t *p, *t;

	list_for_each_entry_safe(p, t, &cgp_list, list)
		cgp_free(p);
	INIT_LIST_HEAD(&cgp_list);
}
