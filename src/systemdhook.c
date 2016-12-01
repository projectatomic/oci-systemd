#define _GNU_SOURCE
#include <stdio.h>
#include <libgen.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mount.h>
#include <syslog.h>
#include <sys/stat.h>
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

#include <libmount/libmount.h>


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

static inline void mnt_free_iterp(struct libmnt_iter **itr) {
	if (*itr)
		mnt_free_iter(*itr);
	*itr=NULL;
}

static inline void mnt_free_fsp(struct libmnt_fs **itr) {
	if (*itr)
		mnt_free_fs(*itr);
	*itr=NULL;
}

#define _cleanup_free_ _cleanup_(freep)
#define _cleanup_close_ _cleanup_(closep)
#define _cleanup_fclose_ _cleanup_(fclosep)
#define _cleanup_mnt_iter_ _cleanup_(mnt_free_iterp)
#define _cleanup_mnt_fs_ _cleanup_(mnt_free_fsp)

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

static int bind_mount(const char *src, const char *dest, int readonly) {
	if (mount(src, dest, "bind", MS_BIND, NULL) == -1) {
		pr_perror("Failed to mount %s on %s", src, dest);
		return -1;
	}
	//  Remount bind mount to read/only if requested by the caller
	if (readonly) {
		if (mount(src, dest, "bind", MS_REMOUNT|MS_BIND|MS_RDONLY, "") == -1) {
			pr_perror("Failed to remount %s readonly", dest);
			return -1;
		}
	}
	return 0;
}

/* error callback */
static int parser_errcb(struct libmnt_table *tb __attribute__ ((__unused__)),
			const char *filename, int line)
{
	pr_perror("%s: parse error at line %d", filename, line);
	return 0;
}

static struct libmnt_table *parse_tabfile(const char *path)
{
	int rc;
	struct libmnt_table *tb = mnt_new_table();

	if (!tb) {
		pr_perror("failed to initialize libmount table");
		return NULL;
	}

	mnt_table_set_parser_errcb(tb, parser_errcb);

	rc = mnt_table_parse_file(tb, path);

	if (rc) {
		mnt_free_table(tb);
		pr_perror("can't read %s", path);
		return NULL;
	}
	return tb;
}

/* reads filesystems from @tb (libmount) looking for cgroup file systems
   then bind mounts these file systems over rootfs
 */
static int mount_cgroup(struct libmnt_table *tb,
			struct libmnt_fs *fs,
			const char *rootfs)
{
	_cleanup_mnt_fs_ struct libmnt_fs *chld = NULL;
	_cleanup_mnt_iter_ struct libmnt_iter *itr = NULL;

	if (!fs) {
		/* first call, get root FS */
		if (mnt_table_get_root_fs(tb, &fs))
			return -1;

	}

	itr = mnt_new_iter(MNT_ITER_FORWARD);
	if (!itr)
		return -1;

	/*
	 * add all children to the output table
	 */
	while (mnt_table_next_child_fs(tb, itr, fs, &chld) == 0) {
		const char *src = mnt_fs_get_target(chld);
		if (strncmp(src, CGROUP_ROOT, strlen(CGROUP_ROOT)) == 0) {
			char dest[PATH_MAX];
			snprintf(dest, PATH_MAX, "%s%s", rootfs, src);

			if (makepath(dest, 0755) == -1) {
				if (errno != EEXIST) {
					pr_perror("Failed to mkdir container cgroup dir: %s", dest);
					return -1;
				}
			}
			/* Running systemd in a container requires you to 
			   mount all cgroup file systems readonly except 
			   /sys/fs/cgroup/systemd 
			*/
			int readonly = (strcmp(src,"/sys/fs/cgroup/systemd") != 0);
			if (bind_mount(src, dest, readonly) < 0) {
				return -1;
			}
		}
		if (mount_cgroup(tb, chld, rootfs))
			return -1;
	}
	return 0;
}

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

static bool contains_mount(const char **config_mounts, unsigned len, const char *mount) {
	for (unsigned i = 0; i < len; i++) {
		if (!strcmp(mount, config_mounts[i])) {
			pr_pdebug("%s already present as a mount point in container configuration, skipping\n", mount);
			return true;
		}
	}
	return false;
}

/*
 * Move specified mount to temporary directory
 */
static int move_mount_to_runtmp(const char *rootfs, const char *run_tmp_dir, const char *mount_dir)
{
	int rc;
	_cleanup_free_ char *src = NULL;
	_cleanup_free_ char *dest = NULL;
	_cleanup_free_ char *post = NULL;
	const char *ptr = NULL;

	rc = asprintf(&src, "%s/%s", rootfs, mount_dir);
	if (rc < 0) {
		pr_perror("Failed to allocate memory for src");
		return -1;
	}

	/* Find the second '/' to get the postfix */
	ptr = strchr(mount_dir, '/');
	ptr++;
	ptr = strchr(ptr, '/');
	post = strdup(ptr);
	if (!post) {
		pr_perror("Failed to allocate memory for postfix");
		return -1;
	}

	rc = asprintf(&dest, "%s/%s", run_tmp_dir, post);
	if (rc < 0) {
		pr_perror("Failed to allocate memory for dest");
		return -1;
	}

	if (makepath(dest, 0755) == -1) {
		if (errno != EEXIST) {
			pr_perror("Failed to mkdir new dest: %s", dest);
			return -1;
		}
	}

	/* Move the mount to temporary directory */
	if ((mount(src, dest, "", MS_MOVE, "") == -1)) {
		pr_perror("Failed to move mount %s to %s", src, dest);
		return -1;
	}

	return 0;
}

#define RUN_PREFIX "/run/"

/*
 * Move the mounts under /run to temporary directory under /tmp (on the host)
 */
static int adjust_run_mounts(const char *rootfs,
		 const char *run_tmp_dir,
		 const char **config_mounts,
		 unsigned len)
{
	int rc = -1;
	struct stat secrets_st = {0};
	struct stat run_st = {0};
	_cleanup_free_ char *run_secrets_dir = NULL;
	_cleanup_free_ char *run_dir = NULL;

	rc = asprintf(&run_dir, "%s/%s", rootfs, "run");
	if (rc < 0) {
		pr_perror("Failed to allocate memory for run_dir");
		return -1;
	}

	rc = asprintf(&run_secrets_dir, "%s/%s", rootfs, "run/secrets");
	if (rc < 0) {
		pr_perror("Failed to allocate memory for run_secrets_dir");
		return -1;
	}

	/* Move /run/secrets to temporary directory if it exists and it is a mountpoint */
	if (stat(run_dir, &run_st) == 0 &&
	    stat(run_secrets_dir, &secrets_st) == 0 &&
	    secrets_st.st_rdev != run_st.st_rdev &&
	    (S_ISDIR(secrets_st.st_mode))) {
		if (move_mount_to_runtmp(rootfs, run_tmp_dir, "/run/secrets") < 0) {
			pr_perror("Failed to move %s to %s", run_secrets_dir, run_tmp_dir);
			return -1;
		}
	}

	/* Move other user specified mounts under /run to temporary directory */
	for (unsigned i = 0; i < len; i++) {
		/* Match destinations that begin with /run/ */
		if (!strncmp(RUN_PREFIX, config_mounts[i], strlen(RUN_PREFIX))) {
			if (move_mount_to_runtmp(rootfs, run_tmp_dir, config_mounts[i]) < 0) {
				pr_perror("Failed to move %s to %s", config_mounts[i], run_tmp_dir);
				return -1;
			}
		}
	}

	return 0;
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

	char run_dir[PATH_MAX];
	snprintf(run_dir, PATH_MAX, "%s/run", rootfs);

	/* Create a temporary directory to move the /run mounts to */
	char temp_template[] = "/tmp/runtmp.XXXXXX";

	char *run_tmp_dir = mkdtemp(temp_template);
	if (run_tmp_dir == NULL) {
		pr_perror("Failed to create temporary directory for /run mounts");
		return -1;
	}

	/* Create the /run directory */
	if (!contains_mount(config_mounts, config_mounts_len, "/run")) {
		if (mkdir(run_dir, 0755) == -1) {
			if (errno != EEXIST) {
				pr_perror("Failed to mkdir: %s", run_dir);
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

		/* Mount tmpfs at new temp directory */
		if (mount("tmpfs", run_tmp_dir, "tmpfs", MS_NODEV|MS_NOSUID|MS_NOEXEC, options) == -1) {
			pr_perror("Failed to mount tmpfs at %s", run_tmp_dir);
			return -1;
		}

		/* Adjust the mount hierarchy under /run */
		if (adjust_run_mounts(rootfs, run_tmp_dir, config_mounts, config_mounts_len) < 0) {
			pr_perror("Failed to set hierarchy under /run");
			return -1;
		}

		/* Move temporary directory to /run */
		if ((mount(run_tmp_dir, run_dir, "", MS_MOVE, "") == -1)) {
			pr_perror("Failed to move mount %s to %s", run_tmp_dir, run_dir);
			return -1;
		}
	}

	/* Remove the temp directory for /run */
	if (rmdir(run_tmp_dir) < 0) {
		pr_perror("Failed to remove %s", run_tmp_dir);
		return -1;
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
				pr_perror("Failed to mkdir: %s", tmp_dir);
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
		char journal_dir[PATH_MAX];
		snprintf(journal_dir, PATH_MAX, "/var/log/journal/%.32s", id);
		char cont_journal_dir[PATH_MAX];
		snprintf(cont_journal_dir, PATH_MAX, "%s%s", rootfs, journal_dir);
		if (makepath(journal_dir, 0755) == -1) {
			if (errno != EEXIST) {
				pr_perror("Failed to mkdir journal dir: %s", journal_dir);
				return -1;
			}
		}

		if (strcmp("", mount_label)) {
			rc = setfilecon(journal_dir, (security_context_t)mount_label);
			if (rc < 0) {
				pr_perror("Failed to set journal dir selinux context");
				return -1;
			}
		}

		if (makepath(cont_journal_dir, 0755) == -1) {
			if (errno != EEXIST) {
				pr_perror("Failed to mkdir container journal dir: %s", cont_journal_dir);
				return -1;
			}
		}

		/* Mount journal directory at /var/log/journal in the container */
		if (bind_mount(cont_journal_dir, cont_journal_dir, false) == -1) {
			return -1;
		}
	}

	if (!contains_mount(config_mounts, config_mounts_len, "/sys/fs/cgroup")) {
		/* libmount */
		struct libmnt_table *tb = NULL;
		int rc = -1;

		/*
		 * initialize libmount
		 */
		mnt_init_debug(0);

		tb = parse_tabfile("/proc/self/mountinfo");
		if (!tb) {
			return -1;
		}

		rc = mount_cgroup(tb, NULL, rootfs);
		mnt_free_table(tb);
		if (rc == -1) {
			return -1;
		}
	}

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

#define DOCKER_CONTAINER "docker"

int main(int argc, char *argv[])
{
	size_t rd;
	_cleanup_(yajl_tree_freep) yajl_val node = NULL;
	_cleanup_(yajl_tree_freep) yajl_val config_node = NULL;
	char errbuf[BUFLEN];
	char stateData[CONFIGSZ];
	char configData[CONFIGSZ];
	_cleanup_fclose_ FILE *fp = NULL;
	bool docker = false;

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

	const char *ctr = getenv("container");
	if (ctr && !strncmp(ctr, DOCKER_CONTAINER, strlen(DOCKER_CONTAINER))) {
		docker = true;
	}

	if (docker) {
		if (argc < 3) {
			pr_perror("cannot find config file to use");
			return EXIT_FAILURE;
		}

		fp = fopen(argv[2], "r");
	} else {
		/* bundle_path must be specified for the OCI hooks, and from there we read the configuration file.
		   If it is not specified, then check that it is specified on the command line.  */
		const char *bundle_path[] = { "bundlePath", (const char *)0 };
		yajl_val v_bundle_path = yajl_tree_get(node, bundle_path, yajl_t_string);
		if (v_bundle_path) {
			char config_file_name[PATH_MAX];
			sprintf(config_file_name, "%s/config.json", YAJL_GET_STRING(v_bundle_path));
			fp = fopen(config_file_name, "r");
		}
	}


	/* Parse the config file */
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

	char *cmd = NULL;
	char *mount_label = NULL;
	const char **config_mounts = NULL;
	unsigned config_mounts_len = 0;

	const char *linux_path[] = { "linux", (const char *)0 };

	if (!docker) {
		/* Extract values from the config json */
		const char *mount_label_path[] = { "linux", "mountLabel", (const char *)0 };
		yajl_val v_mount = yajl_tree_get(config_node, mount_label_path, yajl_t_string);
		mount_label = v_mount ? YAJL_GET_STRING(v_mount) : "";

		const char *mount_points_path[] = {"mounts", (const char *)0 };
		yajl_val v_mounts = yajl_tree_get(config_node, mount_points_path, yajl_t_array);
		if (!v_mounts) {
			pr_perror("mounts not found in config");
			return EXIT_FAILURE;
		}

		config_mounts_len = YAJL_GET_ARRAY(v_mounts)->len;
		config_mounts = malloc (sizeof(char *) * (config_mounts_len + 1));
		if (! config_mounts) {
			pr_perror("error malloc'ing");
			return EXIT_FAILURE;
		}

		for (unsigned int i = 0; i < config_mounts_len; i++) {
			yajl_val v_mounts_values = YAJL_GET_ARRAY(v_mounts)->values[i];

			const char *destination_path[] = {"destination", (const char *)0 };
			yajl_val v_destination = yajl_tree_get(v_mounts_values, destination_path, yajl_t_string);
			if (!v_destination) {
				pr_perror("Cannot find mount destination");
				return EXIT_FAILURE;
			}
			config_mounts[i] = YAJL_GET_STRING(v_destination);
		}

		const char *args_path[] = {"process", "args", (const char *)0 };
		yajl_val v_args = yajl_tree_get(config_node, args_path, yajl_t_array);
		if (!v_args) {
			pr_perror("args not found in config");
			return EXIT_FAILURE;
		}
		yajl_val v_arg0_value = YAJL_GET_ARRAY(v_args)->values[0];
		cmd = YAJL_GET_STRING(v_arg0_value);
	} else {
		/* Handle the Docker case here.  */

		/* Extract values from the config json */
		const char *mount_label_path[] = { "MountLabel", (const char *)0 };
		yajl_val v_mount = yajl_tree_get(config_node, mount_label_path, yajl_t_string);
		if (!v_mount) {
			pr_perror("MountLabel not found in config");
			return EXIT_FAILURE;
		}
		mount_label = YAJL_GET_STRING(v_mount);

		/* Extract values from the config json */
		const char *mount_points_path[] = { "MountPoints", (const char *)0 };
		yajl_val v_mps = yajl_tree_get(config_node, mount_points_path, yajl_t_object);
		if (!v_mps) {
			pr_perror("MountPoints not found in config");
			return EXIT_FAILURE;
		}

		config_mounts = YAJL_GET_OBJECT(v_mps)->keys;
		config_mounts_len = YAJL_GET_OBJECT(v_mps)->len;

		const char *cmd_path[] = { "Path", (const char *)0 };
		yajl_val v_cmd = yajl_tree_get(config_node, cmd_path, yajl_t_string);
		if (!v_cmd) {
			pr_perror("Path not found in config");
			return EXIT_FAILURE;
		}
		cmd = YAJL_GET_STRING(v_cmd);
	}

#ifdef ARGS_CHECK
	/* Don't do anything if init is actually docker bind mounted /dev/init */
	if (!strcmp(cmd, "/dev/init")) {
		pr_pdebug("Skipping as container command is /dev/init, not systemd init\n");
		return EXIT_SUCCESS;
	}
	char *cmd_file_name = basename(cmd);
	if (strcmp("init", cmd_file_name) && strcmp("systemd", cmd_file_name)) {
		pr_pdebug("Skipping as container command is %s, not init or systemd\n", cmd);
		return EXIT_SUCCESS;
	}
#endif

	/* OCI hooks set target_pid to 0 on poststop, as the container process already
	   exited.  If target_pid is bigger than 0 then it is the prestart hook.  */
	if ((argc > 2 && !strcmp("prestart", argv[1])) || target_pid) {
		if (prestart(rootfs, id, target_pid, mount_label, config_mounts, config_mounts_len) != 0) {
			return EXIT_FAILURE;
		}
	} else if ((argc > 2 && !strcmp("poststop", argv[1])) || (target_pid == 0)) {
		if (poststop(rootfs, id, target_pid, config_mounts, config_mounts_len) != 0) {
			return EXIT_FAILURE;
		}
	} else {
		pr_perror("command not recognized: %s", argv[1]);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
