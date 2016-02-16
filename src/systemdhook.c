#define _GNU_SOURCE
#include <stdio.h>
#include <libgen.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mount.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/limits.h>
#include <selinux/selinux.h>
#include <yajl/yajl_tree.h>

#include "config.h"

#define _cleanup_(x) __attribute__((cleanup(x)))

static inline void freep(void *p) {
	free(*(void**) p);
}

static inline void closep(int *fd) {
	if (*fd >= 0)
		close(*fd);
	*fd = -1;
}

static inline void fclosep(FILE **fp) {
	if (*fp)
		fclose(*fp);
	*fp = NULL;
}

#define _cleanup_free_ _cleanup_(freep)
#define _cleanup_close_ _cleanup_(closep)
#define _cleanup_fclose_ _cleanup_(fclosep)

#define DEFINE_CLEANUP_FUNC(type, func)                         \
	static inline void func##p(type *p) {                   \
		if (*p)                                         \
			func(*p);                               \
	}                                                       \

DEFINE_CLEANUP_FUNC(yajl_val, yajl_tree_free)

#define pr_perror(fmt, ...) syslog(LOG_ERR, "systemdhook <error>: " fmt ": %m\n", ##__VA_ARGS__)
#define pr_pinfo(fmt, ...) syslog(LOG_INFO, "systemdhook <info>: " fmt "\n", ##__VA_ARGS__)
#define pr_pdebug(fmt, ...) syslog(LOG_DEBUG, "systemdhook <debug>: " fmt "\n", ##__VA_ARGS__)

#define BUFLEN 1024
#define CONFIGSZ 65536

#define CGROUP_ROOT "/sys/fs/cgroup"

/*
 * Get the contents of the file specified by its path
 */
static char *get_file_contents(const char *path) {
	_cleanup_close_ int fd = -1;
	if ((fd = open(path, O_RDONLY)) == -1) {
		pr_perror("Failed to open file for reading");
		return NULL;
	}

	char buffer[256];
	size_t rd;
	rd = read(fd, buffer, 256);
	if (rd == -1) {
		pr_perror("Failed to read file contents");
		return NULL;
	}

	buffer[rd] = '\0';

	return strdup(buffer);
}

/*
 * Get the cgroup file system path for the specified process id
 */
static char *get_process_cgroup_subsystem_path(int pid, const char *subsystem) {
	_cleanup_free_ char *cgroups_file_path = NULL;
	int rc;
	rc = asprintf(&cgroups_file_path, "/proc/%d/cgroup", pid);
	if (rc < 0) {
		pr_perror("Failed to allocate memory for cgroups file path");
		return NULL;
	}

	_cleanup_fclose_ FILE *fp = NULL;
	fp = fopen(cgroups_file_path, "r");
	if (fp == NULL) {
		pr_perror("Failed to open cgroups file");
		return NULL;
	}

	_cleanup_free_ char *line = NULL;
	ssize_t read;
	size_t len = 0;
	char *ptr;
	char *path;
	char *subsystem_path = NULL;
	while ((read = getline(&line, &len, fp)) != -1) {
		pr_pdebug("%s", line);
		ptr = strchr(line, ':');
		if (ptr == NULL) {
			pr_perror("Error parsing cgroup, ':' not found: %s", line);
			return NULL;
		}
		pr_pdebug("%s", ptr);
		ptr++;
		if (!strncmp(ptr, subsystem, strlen(subsystem))) {
			pr_pdebug("Found");
			char *path = strchr(ptr, '/');
			if (path == NULL) {
				pr_perror("Error finding path in cgroup: %s", line);
				return NULL;
			}
			pr_pdebug("PATH: %s", path);
			rc = asprintf(&subsystem_path, "%s/%s%s", CGROUP_ROOT, subsystem, path);
			if (rc < 0) {
				pr_perror("Failed to allocate memory for subsystemd path");
				return NULL;
			}
			pr_pdebug("SUBSYSTEM_PATH: %s", subsystem_path);
			subsystem_path[strlen(subsystem_path) - 1] = '\0';
			return subsystem_path;
		}
	}

	return NULL;
}

static int makepath(char *dir, mode_t mode)
{
    if (!dir) {
	errno = EINVAL;
	return -1;
    }

    if (strlen(dir) == 1 && dir[0] == '/')
	return 0;

    makepath(dirname(strdupa(dir)), mode);

    return mkdir(dir, mode);
}

bool contains_mount(const char **config_mounts, unsigned len, const char *mount) {
	for (unsigned i = 0; i < len; i++) {
		if (!strcmp(mount, config_mounts[i])) {
			pr_pdebug("%s already present as a mount point in container configuration, skipping\n", mount);
			return true;
		}
	}
	return false;
}

static int prestart(const char *rootfs,
		const char *id,
		int pid,
		const char *mount_label,
		const char **config_mounts,
		unsigned config_mounts_len)
{
	_cleanup_close_  int fd = -1;
	_cleanup_free_   char *options = NULL;

	int rc = -1;
	char process_mnt_ns_fd[PATH_MAX];
	snprintf(process_mnt_ns_fd, PATH_MAX, "/proc/%d/ns/mnt", pid);

	fd = open(process_mnt_ns_fd, O_RDONLY);
	if (fd < 0) {
		pr_perror("Failed to open mnt namespace fd %s", process_mnt_ns_fd);
		return -1;
	}

	/* Join the mount namespace of the target process */
	if (setns(fd, 0) == -1) {
		pr_perror("Failed to setns to %s", process_mnt_ns_fd);
		return -1;
	}
	close(fd);
	fd = -1;

	/* Switch to the root directory */
	if (chdir("/") == -1) {
		pr_perror("Failed to chdir");
		return -1;
	}

	struct statvfs fs_stat;

	/* Stat the rootfs to see if it is a --read-only mount */
	if (statvfs(rootfs, &fs_stat) == -1) {
		pr_perror("Can't stat %s", rootfs);
		return -1;
	}

	if (fs_stat.f_flag & ST_RDONLY) {
		if (mount(rootfs, rootfs, "bind", MS_REMOUNT|MS_BIND|MS_REC, "rw") == -1) {
			pr_perror("Failed to remount %s", rootfs);
			return -1;
		}
	}

	char run_dir[PATH_MAX];
	snprintf(run_dir, PATH_MAX, "%s/run", rootfs);

	/* Create the /run directory */
	if (!contains_mount(config_mounts, config_mounts_len, "/run")) {
		if (mkdir(run_dir, 0755) == -1) {
			if (errno != EEXIST) {
				pr_perror("Failed to mkdir");
				return -1;
			}
		}

		if (!strcmp("", mount_label)) {
			rc = asprintf(&options, "mode=755,size=65536k");
		} else {
			rc = asprintf(&options, "mode=755,size=65536k,context=\"%s\"", mount_label);
		}
		if (rc < 0) {
			pr_perror("Failed to allocate memory for context");
			return -1;
		}

		/* Mount tmpfs at /run for systemd */
		if (mount("tmpfs", run_dir, "tmpfs", MS_NODEV|MS_NOSUID|MS_NOEXEC, options) == -1) {
			pr_perror("Failed to mount tmpfs at /run");
			return -1;
		}
	}

	_cleanup_free_ char *memory_cgroup_path = NULL;
	memory_cgroup_path = get_process_cgroup_subsystem_path(pid, "memory");
	if (!memory_cgroup_path) {
		pr_perror("Failed to get memory subsystem path for the process");
		return -1;
	}

	char memory_limit_path[PATH_MAX];
	snprintf(memory_limit_path, PATH_MAX, "%s/memory.limit_in_bytes", memory_cgroup_path);

	pr_pdebug("memory path: %s", memory_limit_path);

	_cleanup_free_ char *memory_limit_str = NULL;
	memory_limit_str = get_file_contents(memory_limit_path);
	if (!memory_limit_str) {
		pr_perror("Failed to get memory limit from cgroups");
		return -1;
	}

	pr_pdebug("LIMIT: %s\n", memory_limit_str);

	uint64_t memory_limit_in_bytes = 0;
	char *ptr = NULL;

	memory_limit_in_bytes = strtoull(memory_limit_str, &ptr, 10);

	pr_pdebug("Limit in bytes: ""%" PRIu64 "\n", memory_limit_in_bytes);

	/* Set it to half of limit in kb */
	uint64_t memory_limit_in_kb = memory_limit_in_bytes / 2048;

	char tmp_dir[PATH_MAX];
	snprintf(tmp_dir, PATH_MAX, "%s/tmp", rootfs);

	/* Create the /tmp directory */
	if (!contains_mount(config_mounts, config_mounts_len, "/tmp")) {
		if (mkdir(tmp_dir, 0755) == -1) {
			if (errno != EEXIST) {
				pr_perror("Failed to mkdir");
				return -1;
			}
		}

		if (!strcmp("", mount_label)) {
			rc = asprintf(&options, "mode=1777,size=%" PRIu64 "k", memory_limit_in_kb);
		} else {
			rc = asprintf(&options, "mode=1777,size=%" PRIu64 "k,context=\"%s\"", memory_limit_in_kb, mount_label);
		}
		if (rc < 0) {
			pr_perror("Failed to allocate memory for context");
			return -1;
		}

		/* Mount tmpfs at /tmp for systemd */
		if (mount("tmpfs", tmp_dir, "tmpfs", MS_NODEV|MS_NOSUID, options) == -1) {
			pr_perror("Failed to mount tmpfs at /tmp");
			return -1;
		}
	}

	if (!contains_mount(config_mounts, config_mounts_len, "/var/log/journal")) {
		char cont_journal_dir[PATH_MAX];
		snprintf(cont_journal_dir, PATH_MAX, "%s/var/log/journal", rootfs);
		if (makepath(cont_journal_dir, 0755) == -1) {
			if (errno != EEXIST) {
				pr_perror("Failed to mkdir container journal dir");
				return -1;
			}
		}

		/* Mount journal directory at /var/log/journal in the container */
		if (mount(cont_journal_dir, cont_journal_dir, "bind", MS_BIND|MS_REC, NULL) == -1) {
			pr_perror("Failed to mount %s", cont_journal_dir);
			return -1;
		}
		if (mount(cont_journal_dir, cont_journal_dir, "bind", MS_REMOUNT|MS_BIND|MS_REC, "rw") == -1) {
			pr_perror("Failed to remount %s", cont_journal_dir);
			return -1;
		}
	}

#if 0
	if (!contains_mount(config_mounts, config_mounts_len, "/sys/fs/cgroup")) {
		char cont_cgroup_dir[PATH_MAX];
		snprintf(cont_cgroup_dir, PATH_MAX, "%s/sys/fs/cgroup", rootfs);

		if (makepath(cont_cgroup_dir, 0755) == -1) {
			if (errno != EEXIST) {
				pr_perror("Failed to mkdir container cgroup dir");
				goto out;
			}
		}

		/* Mount cgroup directory at /sys/fs/cgroup in the container */
		if (mount("/sys/fs/cgroup", cont_cgroup_dir, "bind", MS_BIND|MS_REC, "ro") == -1) {
			pr_perror("Failed to mount /sys/fs/cgroup at %s", cont_cgroup_dir);
			goto out;
		}
	}
#endif
	if (!contains_mount(config_mounts, config_mounts_len, "/etc/machine-id")) {
		char mid_path[PATH_MAX];
		snprintf(mid_path, PATH_MAX, "%s/etc/machine-id", rootfs);
		fd = open(mid_path, O_CREAT|O_WRONLY, 0444);
		if (fd < 0) {
			pr_perror("Failed to open %s for writing", mid_path);
			return -1;
		}

		rc = dprintf(fd, "%.32s\n", id);
		if (rc < 0) {
			pr_perror("Failed to write id to %s", mid_path);
			return -1;
		}
	}

	if (fs_stat.f_flag & ST_RDONLY) {
		if (mount(rootfs, rootfs, "bind", MS_REMOUNT|MS_BIND|MS_REC, "ro") == -1) {
			pr_perror("Failed to remount %s", rootfs);
			return -1;
		}
	}
	return 0;
}

static int poststop(const char *rootfs,
		const char *id,
		int pid,
		const char **config_mounts,
		unsigned config_mounts_len)
{
	if (contains_mount(config_mounts, config_mounts_len, "/etc/machine-id")) {
		return 0;
	}

	int ret = 0;
	char mid_path[PATH_MAX];
	snprintf(mid_path, PATH_MAX, "%s/etc/machine-id", rootfs);

	if (unlink(mid_path) != 0 && (errno != ENOENT)) {
		pr_perror("Unable to remove %s", mid_path);
		ret = 1;
	}

	return ret;
}

int main(int argc, char *argv[])
{

	if (argc < 3) {
		pr_perror("Expect atleast 2 arguments");
		exit(1);
	}

	size_t rd;
	_cleanup_(yajl_tree_freep) yajl_val node = NULL;
	_cleanup_(yajl_tree_freep) yajl_val config_node = NULL;
	char errbuf[BUFLEN];
	char stateData[CONFIGSZ];
	char configData[CONFIGSZ];
	int ret = -1;
	_cleanup_fclose_ FILE *fp = NULL;

	stateData[0] = 0;
	errbuf[0] = 0;

	/* Read the entire config file from stdin */
	rd = fread((void *)stateData, 1, sizeof(stateData) - 1, stdin);
	if (rd == 0 && !feof(stdin)) {
		pr_perror("Error encountered on file read");
		return EXIT_FAILURE;
	} else if (rd >= sizeof(stateData) - 1) {
		pr_perror("Config file too big");
		return EXIT_FAILURE;
	}

	/* Parse the state */
	node = yajl_tree_parse((const char *)stateData, errbuf, sizeof(errbuf));
	if (node == NULL) {
		pr_perror("parse_error: ");
		if (strlen(errbuf)) {
			pr_perror(" %s", errbuf);
		} else {
			pr_perror("unknown error");
		}
		return EXIT_FAILURE;
	}

	/* Extract values from the state json */
	const char *root_path[] = { "root", (const char *)0 };
	yajl_val v_root = yajl_tree_get(node, root_path, yajl_t_string);
	if (!v_root) {
		pr_perror("root not found in state");
		return EXIT_FAILURE;
	}
	char *rootfs = YAJL_GET_STRING(v_root);

	const char *pid_path[] = { "pid", (const char *) 0 };
	yajl_val v_pid = yajl_tree_get(node, pid_path, yajl_t_number);
	if (!v_pid) {
		pr_perror("pid not found in state");
		return EXIT_FAILURE;
	}
	int target_pid = YAJL_GET_INTEGER(v_pid);

	const char *id_path[] = { "id", (const char *)0 };
	yajl_val v_id = yajl_tree_get(node, id_path, yajl_t_string);
	if (!v_id) {
		pr_perror("id not found in state");
		return EXIT_FAILURE;
	}
	char *id = YAJL_GET_STRING(v_id);

	/* Parse the config file */
	fp = fopen(argv[2], "r");
	if (fp == NULL) {
		pr_perror("Failed to open config file: %s", argv[2]);
		return EXIT_FAILURE;
	}
	rd = fread((void *)configData, 1, sizeof(configData) - 1, fp);
	if (rd == 0 && !feof(fp)) {
		pr_perror("error encountered on file read");
		return EXIT_FAILURE;
	} else if (rd >= sizeof(configData) - 1) {
		pr_perror("config file too big");
		return EXIT_FAILURE;
	}

	config_node = yajl_tree_parse((const char *)configData, errbuf, sizeof(errbuf));
	if (config_node == NULL) {
		pr_perror("parse_error: ");
		if (strlen(errbuf)) {
			pr_perror(" %s", errbuf);
		} else {
			pr_perror("unknown error");
		}
		return EXIT_FAILURE;
	}

#ifdef ARGS_CHECK
	const char *cmd_path[] = { "Path", (const char *)0 };
	yajl_val v_cmd = yajl_tree_get(config_node, cmd_path, yajl_t_string);
	if (!v_cmd) {
		pr_perror("Path not found in config");
		return EXIT_FAILURE;
	}
	char *cmd = YAJL_GET_STRING(v_cmd);

	char *cmd_file_name = basename(cmd);
	if (strcmp("init", cmd_file_name) && strcmp("systemd", cmd_file_name)) {
		pr_pdebug("Skipping as container command is %s, not init or systemd\n", cmd);
		return EXIT_SUCCESS;
	}
#endif

	/* Extract values from the config json */
	const char *mount_label_path[] = { "MountLabel", (const char *)0 };
	yajl_val v_mount = yajl_tree_get(config_node, mount_label_path, yajl_t_string);
	if (!v_mount) {
		pr_perror("MountLabel not found in config");
		return EXIT_FAILURE;
	}
	char *mount_label = YAJL_GET_STRING(v_mount);

	pr_pdebug("Mount Label parsed as: %s", mount_label);

	/* Extract values from the config json */
	const char *mount_points_path[] = { "MountPoints", (const char *)0 };
	yajl_val v_mps = yajl_tree_get(config_node, mount_points_path, yajl_t_object);
	if (!v_mps) {
		pr_perror("MountPoints not found in config");
		return EXIT_FAILURE;
	}

	const char **config_mounts = YAJL_GET_OBJECT(v_mps)->keys;
	unsigned config_mounts_len = YAJL_GET_OBJECT(v_mps)->len;
	if (!strcmp("prestart", argv[1])) {
		if (prestart(rootfs, id, target_pid, mount_label, config_mounts, config_mounts_len) != 0) {
			return EXIT_FAILURE;
		}
	} else if (!strcmp("poststop", argv[1])) {
		if (poststop(rootfs, id, target_pid, config_mounts, config_mounts_len) != 0) {
			return EXIT_FAILURE;
		}
	} else {
		pr_perror("command not recognized: %s", argv[1]);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
