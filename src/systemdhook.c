#define _GNU_SOURCE
#include <stdio.h>
#include <libgen.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mount.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/limits.h>
#include <selinux/selinux.h>
#include <yajl/yajl_tree.h>
#include <stdbool.h>

#include "config.h"

#include <libmount/libmount.h>

static unsigned long get_mem_total() {
	struct sysinfo info;
	int ret = sysinfo(&info);
	if (ret < 0) {
		return ret;
	}
	return info.totalram;
}

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
#define CHUNKSIZE 4096

#define CGROUP_ROOT "/sys/fs/cgroup"
#define CGROUP_SYSTEMD CGROUP_ROOT"/systemd"

char *shortid(const char *id) {
	return strndup(id, 12);
}

static int makepath(char *dir, mode_t mode)
{
    if (!dir) {
	errno = EINVAL;
	return -1;
    }

    if (strlen(dir) == 1 && dir[0] == '/')
	return 0;

    if (makepath(dirname(strdupa(dir)), mode) < 0 && errno != EEXIST)
      return -1;

    return mkdir(dir, mode);
}

static int makefilepath(char *file, mode_t mode)
{
    if (makepath(dirname(strdupa(file)), mode) < 0 && errno != EEXIST)
      return -1;

    int fd = creat(file, mode);
    if (fd != -1) {
	    close(fd);
	    return 0;
    }
    return fd;
}

static int remount_readonly(const char *id, const char *src, const char* dest) {

	struct statfs statfs_buf;
	if (statfs(src, &statfs_buf) < 0) {
		pr_perror("%s: Failed to stat %s", id, src);
		return -1;
	}

	if (mount(src, dest, "bind", MS_REMOUNT|MS_BIND|MS_RDONLY | statfs_buf.f_flags, "") == -1) {
		pr_perror("%s: Failed to remount %s readonly", id, dest);
		return -1;
	}
	return 0;
}

static int bind_mount(const char *id, const char *src, const char *dest, int readonly) {
	if (mount(src, dest, "bind", MS_BIND, NULL) == -1) {
		pr_perror("%s: Failed to mount %s on %s", id, src, dest);
		return -1;
	}
	//  Remount bind mount to read/only if requested by the caller
	if (readonly) {
		if (remount_readonly(id, src, dest) < 0) {
			return -1;
		}
	}
	return 0;
}

static int chperm(const char *id, const char *path, const char *label, uint uid, uint gid, bool doChown) {
	DIR *dir;
	struct dirent *ent;
	if ((dir = opendir (path)) != NULL) {
		/* print all the files and directories within directory */
		while ((ent = readdir (dir)) != NULL) {
			_cleanup_free_ char *full_path = NULL;
			if (asprintf(&full_path, "%s/%s", path, ent->d_name) < 0) {
				pr_perror("%s: Failed to create path for chperm", id);
				closedir(dir);
				return -1;
			}
			if (label != NULL && (strcmp("", label))) {
				if ((is_selinux_enabled() > 0) && (setfilecon (full_path, label) < 0)) {
					pr_perror("%s: Failed to set context %s on %s", id, label, full_path);
				}
			}

			if (doChown) {
				/* Change uid and gid to something the container can handle */
				if (chown(full_path, uid, gid) < 0 ) {
					pr_perror("%s: Failed to chown %d:%d to full_path owner: %s", id, uid, gid, full_path);
				}
			}
		}
		closedir (dir);
	} else {
		/* could not open directory */
		pr_perror("%s: Failed to set labels on %s", id, path);
		return -1;
	}
	return 0;
}

/*
 * Get the contents of the file specified by its path
 */
static char *get_file_contents(const char *id, const char *path) {
	_cleanup_close_ int fd = -1;
	if ((fd = open(path, O_RDONLY)) == -1) {
		pr_perror("%s: Failed to open file for reading", id);
		return NULL;
	}

	char buffer[256];
	ssize_t rd;
	rd = read(fd, buffer, sizeof(buffer)-1);
	if (rd == -1) {
		pr_perror("%s: Failed to read file contents", id);
		return NULL;
	}

	buffer[rd] = '\0';

	return strdup(buffer);
}

/*
 * Get the cgroup file system path for the specified process id
 */
static char *get_process_cgroup_subsystem_path(const char *id, int pid, const char *subsystem) {
	_cleanup_free_ char *cgroups_file_path = NULL;
	int rc;
	rc = asprintf(&cgroups_file_path, "/proc/%d/cgroup", pid);
	if (rc < 0) {
		pr_perror("%s: Failed to allocate memory for cgroups file path", id);
		return NULL;
	}

	_cleanup_fclose_ FILE *fp = NULL;
	fp = fopen(cgroups_file_path, "r");
	if (fp == NULL) {
		pr_perror("%s: Failed to open cgroups file", id);
		return NULL;
	}

	_cleanup_free_ char *line = NULL;
	ssize_t read;
	size_t len = 0;
	char *ptr;
	char *subsystem_path = NULL;
	while ((read = getline(&line, &len, fp)) != -1) {
		pr_pdebug("%s: %s", line, id);
		ptr = strchr(line, ':');
		if (ptr == NULL) {
			pr_perror("%s: Error parsing cgroup, ':' not found: %s", id, line);
			return NULL;
		}
		pr_pdebug("%s: %s", id, ptr);
		ptr++;
		if (!strncmp(ptr, subsystem, strlen(subsystem))) {
			pr_pdebug("%s: Found cgroup", id);
			char *path = strchr(ptr, '/');
			if (path == NULL) {
				pr_perror("%s: Error finding path in cgroup: %s", id, line);
				return NULL;
			}
			pr_pdebug("%s: PATH: %s", id, path);
			const char *subpath = strchr(subsystem, '=');
			if (subpath == NULL) {
				subpath = subsystem;
			} else {
				subpath++;
			}

			rc = asprintf(&subsystem_path, "%s/%s%s", CGROUP_ROOT, subpath, path);
			if (rc < 0) {
				pr_perror("%s: Failed to allocate memory for subsystemd path", id);
				return NULL;
			}
			pr_pdebug("%s: SUBSYSTEM_PATH: %s", id, subsystem_path);
			subsystem_path[strlen(subsystem_path) - 1] = '\0';
			return subsystem_path;
		}
	}

	return NULL;
}

/*
   Mount a tmpfs on the /sys/fs/systemd directory inside of container.
   Create a systemd subdir
   Remount the tmpfs read/only
 */
static int mount_cgroup(const char *id, const char *rootfs, const char *options, char *systemd_path)
{
	_cleanup_free_ char *cgroup_path = NULL;

	if (asprintf(&cgroup_path, "%s/%s", rootfs, CGROUP_ROOT) < 0) {
		pr_perror("%s: Failed to create path for %s", id, CGROUP_ROOT);
		return -1;
	}
	if ((makepath(cgroup_path, 0755) == -1) && (errno != EEXIST)) {
		pr_perror("%s: Failed to mkdir new dest: %s", id, cgroup_path);
		return -1;
	}
	/* Mount tmpfs at new cgroup directory */
	if (mount("tmpfs", cgroup_path, "tmpfs", MS_NODEV|MS_NOSUID, options) == -1) {
		pr_perror("%s: Failed to mount tmpfs at %s", id, cgroup_path);
		return -1;
	}
	if ((makepath(systemd_path, 0755) == -1) && (errno != EEXIST)) {
		pr_perror("%s: Failed to mkdir new dest: %s", id, systemd_path);
		return -1;
	}
	if (remount_readonly(id, cgroup_path, cgroup_path) < 0) {
		return -1;
	}
	return 0;
}

static bool contains_mount(const char *id, const char **config_mounts, unsigned len, const char *mount) {
	for (unsigned i = 0; i < len; i++) {
		if (!strcmp(mount, config_mounts[i])) {
			pr_pdebug("%s: %s already present as a mount point in container configuration, skipping", id, mount);
			return true;
		}
	}
	return false;
}

/*
 * Move specified mount to temporary directory
 */
static int move_mount_to_tmp(const char *id, const char *rootfs, const char *tmp_dir, const char *mount_pnt, int offset)
{
	int rc;
	_cleanup_free_ char *src = NULL;
	_cleanup_free_ char *dest = NULL;
	_cleanup_free_ char *post = NULL;

	rc = asprintf(&src, "%s/%s", rootfs, mount_pnt);
	if (rc < 0) {
		pr_perror("%s: Failed to allocate memory for src", id);
		return -1;
	}

	/* Find the second '/' to get the postfix */
	post = strdup(&mount_pnt[offset]);

	if (!post) {
		pr_perror("%s: Failed to allocate memory for postfix", id);
		return -1;
	}

	rc = asprintf(&dest, "%s/%s", tmp_dir, post);
	if (rc < 0) {
		pr_perror("%s: Failed to allocate memory for dest", id);
		return -1;
	}

	struct stat stat_buf;

	if (stat(src, &stat_buf) == -1) {
		pr_perror("%s: Failed to stat: %s", id, src);
		return -1;
	}

	if (S_ISDIR(stat_buf.st_mode)) {
		if (makepath(dest, 0755) == -1) {
			if (errno != EEXIST) {
				pr_perror("%s: Failed to mkdir new dest: %s", id, dest);
				return -1;
			}
		}
	} else {
		if (makefilepath(dest, 0755) == -1) {
			if (errno != EEXIST) {
				pr_perror("%s: Failed to create new dest: %s", id, dest);
				return -1;
			}
		}
	}

	/* Move the mount to temporary directory */
	if ((mount(src, dest, "", MS_MOVE, "") == -1)) {
		pr_perror("%s: Failed to move mount %s to %s", id, src, dest);
		return -1;
	}

	return 0;
}

static int move_mounts(const char *id,
		       const char *rootfs,
		       const char *path,
		       const char **config_mounts,
		       unsigned config_mounts_len,
		       uint uid,
		       uint gid,
		       char *options
	) {

	char mount_dir[PATH_MAX];
	snprintf(mount_dir, PATH_MAX, "%s%s", rootfs, path);

	/* Create a temporary directory to move the PATH mounts to */
	char temp_template[] = "/tmp/ocitmp.XXXXXX";

	char *tmp_dir = mkdtemp(temp_template);
	if (tmp_dir == NULL) {
		pr_perror("%s: Failed to create temporary directory for mounts", id);
		return -1;
	}

	/* Create the PATH directory */
	if (!contains_mount(id, config_mounts, config_mounts_len, path)) {
		if (mkdir(mount_dir, 0755) == -1) {
			if (errno != EEXIST) {
				pr_perror("%s: Failed to mkdir: %s", id, mount_dir);
				return -1;
			}
		}

		/* Mount tmpfs at new temp directory */
		if (mount("tmpfs", tmp_dir, "tmpfs", MS_NODEV|MS_NOSUID, options) == -1) {
			pr_perror("%s: Failed to mount tmpfs at %s", id, tmp_dir);
			return -1;
		}

		/* Move other user specified mounts under PATH to temporary directory */
		for (unsigned i = 0; i < config_mounts_len; i++) {
			/* Match destinations that begin with PATH */
			if (!strncmp(path, config_mounts[i], strlen(path))) {
				if (move_mount_to_tmp(id, rootfs, tmp_dir, config_mounts[i], strlen(path)) < 0) {
					pr_perror("%s: Failed to move %s to %s", id, config_mounts[i], tmp_dir);
					return -1;
				}
			}
		}

		/* Move temporary directory to PATH */
		if ((mount(tmp_dir, mount_dir, "", MS_MOVE, "") == -1)) {
			pr_perror("%s: Failed to move mount %s to %s", id, tmp_dir, mount_dir);
			return -1;
		}
		if (chown(mount_dir, uid, gid) < 0 ) {
			pr_perror("%s: Failed to chown %d:%d to mount_dir owner: %s", id, uid, gid, mount_dir);
		}
	}

	/* Remove the temp directory for PATH */
	if (rmdir(tmp_dir) < 0) {
		pr_perror("%s: Failed to remove %s", id, tmp_dir);
		return -1;
	}
	return 0;
}

static int prestart(const char *rootfs,
		const char *container_uuid,
		const char *id,
		int pid,
		const char *mount_label,
		const char **config_mounts,
		unsigned config_mounts_len,
		uint uid,
		uint gid)
{
	_cleanup_close_  int fd = -1;
	_cleanup_free_   char *options = NULL;

	int rc = -1;
	char process_mnt_ns_fd[PATH_MAX];
	snprintf(process_mnt_ns_fd, PATH_MAX, "/proc/%d/ns/mnt", pid);

	fd = open(process_mnt_ns_fd, O_RDONLY);
	if (fd < 0) {
		pr_perror("%s: Failed to open mnt namespace fd %s", id, process_mnt_ns_fd);
		return -1;
	}

	/* Join the mount namespace of the target process */
	if (setns(fd, 0) == -1) {
		pr_perror("%s: Failed to setns to %s", id, process_mnt_ns_fd);
		return -1;
	}
	close(fd);
	fd = -1;

	/* Switch to the root directory */
	if (chdir("/") == -1) {
		pr_perror("%s: Failed to chdir", id);
		return -1;
	}

	if (!strcmp("", mount_label)) {
		rc = asprintf(&options, "mode=755,size=65536k");
	} else {
		rc = asprintf(&options, "mode=755,size=65536k,context=\"%s\"", mount_label);
	}
	if (rc < 0) {
		pr_perror("%s: Failed to allocate memory for context", id);
		return -1;
	}

	rc = move_mounts(id, rootfs, "/run", config_mounts, config_mounts_len, uid, gid, options);
	if (rc < 0) {
		return rc;
	}

	rc = move_mounts(id, rootfs, "/run/lock", config_mounts, config_mounts_len, uid, gid, options);
	if (rc < 0) {
		return rc;
	}

	_cleanup_free_ char *memory_cgroup_path = NULL;
	memory_cgroup_path = get_process_cgroup_subsystem_path(id, pid, "memory");
	if (!memory_cgroup_path) {
		pr_perror("%s: Failed to get memory subsystem path for the process", id);
		return -1;
	}

	char memory_limit_path[PATH_MAX];
	snprintf(memory_limit_path, PATH_MAX, "%s/memory.limit_in_bytes", memory_cgroup_path);

	pr_pdebug("%s: memory path: %s", id, memory_limit_path);

	_cleanup_free_ char *memory_limit_str = NULL;
	memory_limit_str = get_file_contents(id, memory_limit_path);
	if (!memory_limit_str) {
		pr_perror("%s: Failed to get memory limit from cgroups", id);
		return -1;
	}

	pr_pdebug("%s: LIMIT: %s", id, memory_limit_str);

	char memory_str[PATH_MAX];
	uint64_t total_memory = 0;
	uint64_t memory_limit_in_bytes = 0;
	char *ptr = NULL;

	memory_limit_in_bytes = strtoull(memory_limit_str, &ptr, 10);

	pr_pdebug("%s: Limit in bytes: ""%" PRIu64 "", id, memory_limit_in_bytes);

	total_memory = get_mem_total();
	if (memory_limit_in_bytes < total_memory) {
		/* Set it to half of limit in kb */
		uint64_t memory_limit_in_kb = memory_limit_in_bytes / 2048;
		snprintf(memory_str, sizeof(memory_str)-1 , ",size=%" PRIu64 "k", memory_limit_in_kb);
	} else {
		strcpy(memory_str, "");
	}

	char tmp_dir[PATH_MAX];
	snprintf(tmp_dir, PATH_MAX, "%s/tmp", rootfs);

	/*
	   Create a /var/log/journal directory on the host and mount it into
	   the container.
	*/
	if (!contains_mount(id, config_mounts, config_mounts_len, "/var/log/journal")) {
		char journal_dir[PATH_MAX];
		snprintf(journal_dir, PATH_MAX, "/var/log/journal/%.32s", container_uuid);
		char cont_journal_dir[PATH_MAX];
		snprintf(cont_journal_dir, PATH_MAX, "%s/var/log/journal", rootfs);
		if (makepath(journal_dir, 0755) == -1) {
			if (errno != EEXIST) {
				pr_perror("%s: Failed to mkdir journal dir: %s", id, journal_dir);
				return -1;
			}
		}

		if (strcmp("", mount_label)) {
			if ((is_selinux_enabled() > 0) &&
			    (setfilecon(journal_dir, (security_context_t)mount_label) < 0)) {
				pr_perror("%s: Failed to set journal dir selinux context", id);
				return -1;
			}
		}

		/* Attempt to creare /var/log/journal inside of rootfs,
		   if successful, or directory exists, mount tmpfs on top of
		   it, so that systemd can write journal to it, even in
		   read/only images
		*/
		if ((makepath(cont_journal_dir, 0755) == 0) ||
		    (errno == EEXIST)) {
			snprintf(cont_journal_dir, PATH_MAX, "%s%s", rootfs, journal_dir);
			/* Mount tmpfs at /var/log/journal for systemd */
			rc = move_mounts(id, rootfs, "/var/log/journal", config_mounts, config_mounts_len, uid, gid, options);
			if (rc < 0) {
				return rc;
			}
		} else {
			/* If you can't create /var/log/journal inside of rootfs,
			   create /run/log/journal instead, systemd should write here
			   if it is not allowed to write to /var/log/journal
			*/
			snprintf(cont_journal_dir, PATH_MAX, "%s/run/log/journal/%.32s", rootfs, container_uuid);
		}

		if ((makepath(cont_journal_dir, 0755) == -1) &&
		    (errno != EEXIST)) {
			pr_perror("%s: Failed to mkdir container journal dir: %s", id, cont_journal_dir);
			return -1;
		}

		/* Mount journal directory at cont_journal_dir path in the container */
		if (bind_mount(id, journal_dir, cont_journal_dir, false) == -1) {
			return -1;
		}

		/* Change perms, uid and gid to something the container can handle */
		if (chperm(id, cont_journal_dir, mount_label, uid, gid, true) < 0) {
			return -1;
		}
	}

	/* Create the /tmp directory */
	if (!contains_mount(id, config_mounts, config_mounts_len, "/tmp")) {
		if (mkdir(tmp_dir, 0755) == -1) {
			if (errno != EEXIST) {
				pr_perror("%s: Failed to mkdir: %s", id, tmp_dir);
				return -1;
			}
		}

		free(options); options=NULL;
		if (!strcmp("", mount_label)) {
			rc = asprintf(&options, "mode=1777%s", memory_str);
		} else {
			rc = asprintf(&options, "mode=1777%s,context=\"%s\"", memory_str, mount_label);
		}
		if (rc < 0) {
			pr_perror("%s: Failed to allocate memory for context", id);
			return -1;
		}

		/* Mount tmpfs at /tmp for systemd */
		rc = move_mounts(id, rootfs, "/tmp", config_mounts, config_mounts_len, uid, gid, options);
		if (rc < 0) {
			return rc;
		}
	}

	/*
	 * initialize libmount
	 */

	/*
	   if CGROUP_ROOT is not bind mounted, we need to create a tmpfs on
	   it, and then create the systemd directory underneath it
	*/

	_cleanup_free_ char *systemd_path = NULL;
	if (asprintf(&systemd_path, "%s/%s", rootfs, CGROUP_SYSTEMD) < 0) {
		pr_perror("%s: Failed to create path for %s", id, CGROUP_ROOT);
		return -1;
	}
	if (!contains_mount(id, config_mounts, config_mounts_len, CGROUP_ROOT)) {
		rc = mount_cgroup(id, rootfs, options, systemd_path);
		if (rc < 0) {
			pr_perror("%s: mount_cgroup failed", id);
			return -1;
		}

	} else {
		if ((makepath(systemd_path, 0755) == -1) && (errno != EEXIST)) {
			pr_perror("%s: Failed to mkdir new dest: %s", id, systemd_path);
			return -1;
		}
	}

	if (bind_mount(id, CGROUP_SYSTEMD, systemd_path, true)) {
		pr_perror("%s: Failed to bind mount %s on %s", id, CGROUP_SYSTEMD, systemd_path);
		return -1;
	}

	/*
	   Mount the writable systemd hierarchy into the container
	*/
	_cleanup_free_ char *named_path = NULL;
	named_path = get_process_cgroup_subsystem_path(id, pid, "name=systemd");
	_cleanup_free_ char *systemd_named_path = NULL;
	if (asprintf(&systemd_named_path, "%s/%s", rootfs, named_path) < 0) {
		pr_perror("%s: Failed to create path for %s/%s", id, rootfs, systemd_named_path);
		return -1;
	}
	if (bind_mount(id, named_path, systemd_named_path, false)) {
		pr_perror("%s: Failed to bind mount %s on %s", id, CGROUP_SYSTEMD, systemd_named_path);
		return -1;
	}

	/***
	* chown will fail on /var/lib/docker files as they are not on the
	* container so let's pass false to not have it done in the chperm
	* function.
	***/
	if (chperm(id, systemd_named_path, mount_label, uid, gid, false) < 0) {
		return -1;
	}

	/***
	* chown files in the /sys/fs/cgroup directory paths to the
	* container's uid and gid, so let's pass true here.
	***/
	if (chperm(id, named_path, mount_label, uid, gid, true) < 0) {
		return -1;
	}

	/*
	   Create /etc/machine-id if it does not exist
	*/
	if (!contains_mount(id, config_mounts, config_mounts_len, "/etc/machine-id")) {
		char mid_path[PATH_MAX];
		snprintf(mid_path, PATH_MAX, "%s/etc/machine-id", rootfs);
		fd = open(mid_path, O_CREAT|O_WRONLY, 0444);
		if (fd < 0) {
			pr_perror("%s: Failed to open %s for writing", id, mid_path);
			return -1;
		}

		rc = dprintf(fd, "%.32s\n", container_uuid);
		if (rc < 0) {
			pr_perror("%s: Failed to write id to %s", id, mid_path);
			return -1;
		}
	}

	return 0;
}

static int poststop(
	const char *id,
	const char *rootfs,
	const char **config_mounts,
	unsigned config_mounts_len)
{
	if (contains_mount(id, config_mounts, config_mounts_len, "/etc/machine-id")) {
		return 0;
	}

	int ret = 0;
	char mid_path[PATH_MAX];
	snprintf(mid_path, PATH_MAX, "%s/etc/machine-id", rootfs);

	if (unlink(mid_path) != 0 && (errno != ENOENT)) {
		pr_perror("%s: Unable to remove %s", id, mid_path);
		ret = 1;
	}

	return ret;
}

/*
 * Read the entire content of stream pointed to by 'from' into a buffer in memory.
 * Return a pointer to the resulting NULL-terminated string.
 */
char *getJSONstring(FILE *from, size_t chunksize, char *msg)
{
	struct stat stat_buf;
	char *err = NULL, *JSONstring = NULL;
	size_t nbytes, bufsize;

	if (fstat(fileno(from), &stat_buf) == -1) {
		err = "fstat failed";
		goto fail;
	}

	if (S_ISREG(stat_buf.st_mode)) {
		/*
		 * If 'from' is a regular file, allocate a buffer based
		 * on the file size and read the entire content with a
		 * single fread() call.
		 */
		if (stat_buf.st_size == 0) {
			err = "is empty";
			goto fail;
		}

		bufsize = (size_t)stat_buf.st_size;

		JSONstring = (char *)malloc(bufsize + 1);
		if (JSONstring == NULL) {
			err = "failed to allocate buffer";
			goto fail;
		}

		nbytes = fread((void *)JSONstring, 1, (size_t)bufsize, from);
		if (nbytes != (size_t)bufsize) {
			err = "error encountered on read";
			goto fail;
		}
	} else {
		/*
		 * If 'from' is not a regular file, call fread() iteratively
		 * to read sections of 'chunksize' bytes until EOF is reached.
		 * Call realloc() during each iteration to expand the buffer
		 * as needed.
		 */
		bufsize = 0;

		for (;;) {
			JSONstring = (char *)realloc((void *)JSONstring, bufsize + chunksize);
			if (JSONstring == NULL) {
				err = "failed to allocate buffer";
				goto fail;
			}

			nbytes = fread((void *)&JSONstring[bufsize], 1, (size_t)chunksize, from);
			bufsize += nbytes;

			if (nbytes != (size_t)chunksize) {
				if (ferror(from)) {
					err = "error encountered on read";
					goto fail;
				}
				if (feof(from))
					break;
			}
		}

		if (bufsize == 0) {
			err = "is empty";
			goto fail;
		}

		JSONstring = (char *)realloc((void *)JSONstring, bufsize + 1);
		if (JSONstring == NULL) {
			err = "failed to allocate buffer";
			goto fail;
		}
	}

	/* make sure the string is NULL-terminated */
	JSONstring[bufsize] = 0;
	return JSONstring;
fail:
	free(JSONstring);
	pr_perror("%s: %s", msg, err);
	return NULL;
}

int main(int argc, char *argv[])
{
	_cleanup_(yajl_tree_freep) yajl_val node = NULL;
	_cleanup_(yajl_tree_freep) yajl_val config_node = NULL;
	char errbuf[PATH_MAX+100];
	char *stateData;
	char *configData;
	char config_file_name[PATH_MAX];
	_cleanup_fclose_ FILE *fp = NULL;

	/* Read the entire state from stdin */
	stateData = getJSONstring(stdin, (size_t)CHUNKSIZE, "failed to read state data from standard input");
	if (stateData == NULL)
		return EXIT_FAILURE;

	/* Parse the state */
	memset(errbuf, 0, sizeof(errbuf));
	node = yajl_tree_parse((const char *)stateData, errbuf, sizeof(errbuf));
	if (node == NULL) {
		if (strlen(errbuf)) {
			pr_perror("parse_error: %s", errbuf);
		} else {
			pr_perror("parse_error: unknown error");
		}
		return EXIT_FAILURE;
	}

	const char *id_path[] = { "id", (const char *)0 };
	yajl_val v_id = yajl_tree_get(node, id_path, yajl_t_string);
	if (!v_id) {
		pr_perror("id not found in state");
		return EXIT_FAILURE;
	}
	char *container_uuid = YAJL_GET_STRING(v_id);
	_cleanup_free_ char *id = NULL;
	id = shortid(container_uuid);
	if (!id) {
		pr_perror("%s: failed to create shortid", container_uuid);
		return EXIT_FAILURE;
	}

	const char *pid_path[] = { "pid", (const char *) 0 };
	yajl_val v_pid = yajl_tree_get(node, pid_path, yajl_t_number);
	if (!v_pid) {
		pr_perror("%s: pid not found in state", id);
		return EXIT_FAILURE;
	}
	int target_pid = YAJL_GET_INTEGER(v_pid);

	/* 'bundle' must be specified for the OCI hooks, and from there we read the configuration file */
	const char *bundle_path[] = { "bundle", (const char *)0 };
	yajl_val v_bundle_path = yajl_tree_get(node, bundle_path, yajl_t_string);
	if (!v_bundle_path) {
		const char *bundle_path[] = { "bundlePath", (const char *)0 };
		v_bundle_path = yajl_tree_get(node, bundle_path, yajl_t_string);
	}
	if (!v_bundle_path) {
		/****
		* On Docker versions prior to 1.12, bundlePath will not
		* be provided.  Let's exit quietly if not found.
		****/
		pr_pinfo("%s: Failed reading state data: bundlePath not found.  Generally this indicates Docker versions prior to 1.12 are installed.", id);
		return EXIT_SUCCESS;
	}
	snprintf(config_file_name, sizeof(config_file_name), "%s/config.json", YAJL_GET_STRING(v_bundle_path));
	fp = fopen(config_file_name, "r");

	if (fp == NULL) {
		pr_perror("%s: Failed to open config file: %s", id, config_file_name);
		return EXIT_FAILURE;
	}

	/* Read the entire config file */
	snprintf(errbuf, sizeof(errbuf), "failed to read config data from %s", config_file_name);
	configData = getJSONstring(fp, (size_t)CHUNKSIZE, errbuf);
	if (configData == NULL)
		return EXIT_FAILURE;

	/* Parse the config file */
	memset(errbuf, 0, sizeof(errbuf));
	config_node = yajl_tree_parse((const char *)configData, errbuf, sizeof(errbuf));
	if (config_node == NULL) {
		if (strlen(errbuf)) {
			pr_perror("%s: parse_error: %s", id, errbuf);
		} else {
			pr_perror("%s: parse_error: unknown error", id);
		}
		return EXIT_FAILURE;
	}

	const char *args_path[] = {"process", "args", (const char *)0 };
	yajl_val v_args = yajl_tree_get(config_node, args_path, yajl_t_array);
	if (!v_args) {
		pr_perror("%s: args not found in config", id);
		return EXIT_FAILURE;
	}

	const char *envs[] = {"process", "env", (const char *)0 };
	yajl_val v_envs = yajl_tree_get(config_node, envs, yajl_t_array);
	if (v_envs) {
		for (unsigned int i = 0; i < YAJL_GET_ARRAY(v_envs)->len; i++) {
			yajl_val v_env = YAJL_GET_ARRAY(v_envs)->values[i];
			char *str = YAJL_GET_STRING(v_env);
			/****
			* If the oci-systemd-hook variable is passed with "disabled",
			* stop execution of oci-systemd-hook.
			******/
			if (strncmp (str, "oci-systemd-hook=", strlen ("oci-systemd-hook=")) == 0) {
				int valStart = strlen(str) - strlen("disabled");
				if (strcasecmp(&str[valStart], "disabled") == 0) {
					return EXIT_SUCCESS;
				}
			}
			if (strncmp (str, "container_uuid=", strlen ("container_uuid=")) == 0) {
				container_uuid = strdup (str + strlen ("container_uuid="));
				/* systemd expects $container_uuid= to be an UUID but then treat it as
					not containing any '-'.  Do the same here.  */
				char *to = container_uuid;
				for (char *from = to; *from; from++) {
					if (*from != '-')
						*to++ = *from;
				}
					*to = '\0';
			}
		}
	}

#if ARGS_CHECK
	char *cmd = NULL;
	yajl_val v_arg0_value = YAJL_GET_ARRAY(v_args)->values[0];
	cmd = YAJL_GET_STRING(v_arg0_value);
	/* Don't do anything if init is actually container runtime bind mounted /dev/init */
	if (!strcmp(cmd, "/dev/init")) {
		pr_pdebug("%s: Skipping as container command is /dev/init, not systemd init", id);
		return EXIT_SUCCESS;
	}
	char *cmd_file_name = basename(cmd);
	if (strcmp("init", cmd_file_name) && strcmp("systemd", cmd_file_name)) {
		pr_pdebug("%s: Skipping as container command is %s, not init or systemd", id, cmd);
		return EXIT_SUCCESS;
	}
#endif

	/* Extract values from the config json */
	const char *root_path[] = { "root", "path", (const char *)0 };
	yajl_val v_root = yajl_tree_get(config_node, root_path, yajl_t_string);
	if (!v_root) {
		pr_perror("%s: root path not found in config.json", id);
		return EXIT_FAILURE;
	}
	char *rootfs = YAJL_GET_STRING(v_root);

	/* Prepend bundle path if the rootfs string is relative */
	if (rootfs[0] != '/') {
		char *new_rootfs;

		if (asprintf(&new_rootfs, "%s/%s", YAJL_GET_STRING(v_bundle_path), rootfs) < 0) {
			pr_perror("%s: failed to alloc rootfs", id);
			return EXIT_FAILURE;
		}
		rootfs = new_rootfs;
	}

	pr_pdebug("%s: rootfs=%s", id, rootfs);
	const char **config_mounts = NULL;
	unsigned config_mounts_len = 0;
	unsigned array_len = 0;

	const char *mount_points_path[] = {"mounts", (const char *)0 };
	yajl_val v_mounts = yajl_tree_get(config_node, mount_points_path, yajl_t_array);
	if (!v_mounts) {
		pr_perror("%s: mounts not found in config", id);
		return EXIT_FAILURE;
	}

	config_mounts_len = YAJL_GET_ARRAY(v_mounts)->len;
	config_mounts = malloc (sizeof(char *) * (config_mounts_len + 1));
	if (! config_mounts) {
		pr_perror("%s: error malloc'ing", id);
		return EXIT_FAILURE;
	}

	for (unsigned int i = 0; i < config_mounts_len; i++) {
		yajl_val v_mounts_values = YAJL_GET_ARRAY(v_mounts)->values[i];

		const char *destination_path[] = {"destination", (const char *)0 };
		yajl_val v_destination = yajl_tree_get(v_mounts_values, destination_path, yajl_t_string);
		if (!v_destination) {
			pr_perror("%s: Cannot find mount destination", id);
			return EXIT_FAILURE;
		}
		config_mounts[i] = YAJL_GET_STRING(v_destination);
	}

	/* OCI hooks set target_pid to 0 on poststop, as the container process
	   already exited.  If target_pid is bigger than 0 then it is a start
	   hook.
	   In most cases the calling program will set the environment variable
	   "stage" to either prestart, poststart or poststop.
	   We also support passing the stage as argv[1],
	   In certain cases we also support passing of no argv[1], and no environment variable,
	   then default to prestart if the target_pid != 0, poststop if target_pid == 0.
	*/
	char *stage = getenv("stage");
	if (stage == NULL && argc > 2) {
		stage = argv[1];
	}
	if ((stage != NULL && !strcmp(stage, "prestart")) ||
	    (argc == 1 && target_pid)) {
		char *mount_label = NULL;
		/* Extract values from the config json */
		const char *mount_label_path[] = { "linux", "mountLabel", (const char *)0 };
		yajl_val v_mount = yajl_tree_get(config_node, mount_label_path, yajl_t_string);
		mount_label = v_mount ? YAJL_GET_STRING(v_mount) : "";

		/* Get the gid value. */
		int gid = -1;
		const char *gid_mappings[] = {"linux", "gidMappings", (const char *)0 };
		yajl_val v_gidMappings = yajl_tree_get(config_node, gid_mappings, yajl_t_array);
		if (!v_gidMappings) {
			pr_pdebug("%s: gidMappings not found in config", id);
			gid=0;
		}

		const char *container_path[] = {"containerID", (const char *)0 };
		if (gid != 0) {
			array_len = YAJL_GET_ARRAY(v_gidMappings)->len;
			if (array_len < 1) {
				pr_perror("%s: No gid for container found", id);
				return EXIT_FAILURE;
			}

			const char *gid_path[] = {"hostID", (const char *)0 };
			for (unsigned int i = 0; i < array_len; i++) {
				yajl_val v_gidMappings_values = YAJL_GET_ARRAY(v_gidMappings)->values[i];
				yajl_val v_containerId = yajl_tree_get(v_gidMappings_values, container_path, yajl_t_number);
				if (YAJL_GET_INTEGER(v_containerId) == 0) {
					yajl_val v_gid = yajl_tree_get(v_gidMappings_values, gid_path, yajl_t_number);
					gid = v_gid ? YAJL_GET_INTEGER(v_gid) : -1;
					i = array_len;
				}
			}
		} /* End if (gid!=0) */

		pr_pdebug("%s: GID: %d", id, gid);

		/* Get the uid value. */
		int uid = -1;
		const char *uid_mappings[] = {"linux", "uidMappings", (const char *)0 };
		yajl_val v_uidMappings = yajl_tree_get(config_node, uid_mappings, yajl_t_array);
		if (!v_uidMappings) {
			pr_pdebug("%s: uidMappings not found in config", id);
			uid = 0;
		}

		if (uid !=0) {
			array_len = YAJL_GET_ARRAY(v_uidMappings)->len;
			if (array_len < 1) {
				pr_perror("%s: No uid for container found", id);
				return EXIT_FAILURE;
			}

			const char *uid_path[] = {"hostID", (const char *)0 };
			for (unsigned int i = 0; i < array_len; i++) {
				yajl_val v_uidMappings_values = YAJL_GET_ARRAY(v_uidMappings)->values[i];
				yajl_val v_containerId = yajl_tree_get(v_uidMappings_values, container_path, yajl_t_number);
				if (YAJL_GET_INTEGER(v_containerId) == 0) {
					yajl_val v_uid = yajl_tree_get(v_uidMappings_values, uid_path, yajl_t_number);
					uid = v_uid ? YAJL_GET_INTEGER(v_uid) : -1;
					i = array_len;
				}
			}
		} /* End if (uid !=0) */

		pr_pdebug("%s: UID: %d", id, uid);

		if (prestart(rootfs, container_uuid, id, target_pid, mount_label, config_mounts, config_mounts_len, uid, gid) != 0) {
			return EXIT_FAILURE;
		}
	/* If caller did not specify argv[1], and target_pid == 0, we default
	   to postop.
	*/
	} else if ((stage != NULL && !strcmp(stage, "poststop")) ||
		   (argc == 1 && target_pid == 0)) {
		if (poststop(id, rootfs, config_mounts, config_mounts_len) != 0) {
			return EXIT_FAILURE;
		}
	} else {
		pr_pdebug("%s: only runs in prestart and poststop stage, ignoring", id);
	}
	free(config_mounts);
	return EXIT_SUCCESS;
}
