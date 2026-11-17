/* Linux fixture only: fault regular queue/raw files under one private /tmp tree.
 * The shared library is injected into an explicitly selected collector child;
 * it is never part of the installed collector or its production configuration.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static const char *root, *gate, *events, *mode;
static ssize_t (*next_write)(int, const void *, size_t);
static ssize_t (*next_read)(int, void *, size_t);
static int (*next_fstat)(int, struct stat *);
static int (*next_fdatasync)(int), (*next_fsync)(int);
static int (*next_rename)(const char *, const char *);
static int (*next_stat)(const char *, struct stat *), (*next_unlink)(const char *);
static atomic_int partial_done, checkpoint_renamed, rotation_seen;

enum file_kind { OTHER, QUEUE_DATA, CHECKPOINT, QUEUE_DIRECTORY, RAW };

__attribute__((constructor)) static void initialize(void) {
    next_write = dlsym(RTLD_NEXT, "write");
    next_read = dlsym(RTLD_NEXT, "read");
    next_fstat = dlsym(RTLD_NEXT, "fstat");
    next_fdatasync = dlsym(RTLD_NEXT, "fdatasync");
    next_fsync = dlsym(RTLD_NEXT, "fsync");
    next_rename = dlsym(RTLD_NEXT, "rename");
    next_stat = dlsym(RTLD_NEXT, "stat");
    next_unlink = dlsym(RTLD_NEXT, "unlink");
    root = getenv("FLS_FIXTURE_FAULT_ROOT");
    gate = getenv("FLS_FIXTURE_FAULT_GATE");
    events = getenv("FLS_FIXTURE_FAULT_EVENTS");
    mode = getenv("FLS_FIXTURE_FAULT_MODE");
    if (!root || strncmp(root, "/tmp/fls-community-collector-", 29) ||
        !gate || !events || !mode) root = NULL;
    if (root && (strncmp(gate, root, strlen(root)) ||
        strcmp(gate + strlen(root), "/fault.enabled") ||
        strncmp(events, root, strlen(root)) ||
        strcmp(events + strlen(root), "/fault.events"))) root = NULL;
}

static enum file_kind kind(int fd) {
    char descriptor[64], path[PATH_MAX];
    struct stat info;
    if (!root || syscall(SYS_fstat, fd, &info)) return OTHER;
    snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", fd);
    ssize_t length = syscall(SYS_readlinkat, AT_FDCWD, descriptor, path, sizeof(path) - 1);
    if (length < 0 || length >= (ssize_t)sizeof(path) - 1) return OTHER;
    path[length] = 0;
    size_t prefix = strlen(root);
    if (strncmp(path, root, prefix) || path[prefix] != '/') return OTHER;
    const char *relative = path + prefix + 1;
    if (S_ISDIR(info.st_mode) && !strcmp(relative, "queue")) return QUEUE_DIRECTORY;
    if (!S_ISREG(info.st_mode)) return OTHER;
    if (!strcmp(relative, "queue/fg-receive.qi.tmp") ||
        !strcmp(relative, "queue/fg-receive.qi")) return CHECKPOINT;
    const char *queue = "queue/fg-receive.";
    if (!strncmp(relative, queue, strlen(queue))) {
        const char *number = relative + strlen(queue);
        if (strlen(number) == 8 && strspn(number, "0123456789") == 8) {
            if (strcmp(number, "00000001")) atomic_store(&rotation_seen, 1);
            return QUEUE_DATA;
        }
    }
    if (!strncmp(relative, "raw/", 4) && strlen(relative + 4) == 19 &&
        !strcmp(relative + strlen(relative) - 6, ".jsonl") &&
        strspn(relative + 4, "0123456789-") == 13) return RAW;
    return OTHER;
}

static int enabled(void) {
    struct stat info;
    return root && syscall(SYS_newfstatat, AT_FDCWD, gate, &info, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISREG(info.st_mode) && info.st_uid == geteuid() && !(info.st_mode & 0022);
}

static void record(const char *event) {
    int saved = errno;
    int fd = syscall(SYS_openat, AT_FDCWD, events,
                     O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0);
    if (fd >= 0) {
        syscall(SYS_write, fd, event, strlen(event));
        syscall(SYS_close, fd);
    }
    errno = saved;
}

/* Read-side faults must never affect the queue append descriptor. kind()
 * uses the raw metadata syscall so this fstat wrapper cannot recurse. */
static int queue_reader(int fd) {
    return kind(fd) == QUEUE_DATA && (fcntl(fd, F_GETFL) & O_ACCMODE) == O_RDONLY;
}

int fstat(int fd, struct stat *info) {
    if (root && !strcmp(mode, "queue_reader_fstat") && enabled() && queue_reader(fd)) {
        record("reader_fstat_eio\n");
        errno = EIO;
        return -1;
    }
    return next_fstat ? next_fstat(fd, info) : syscall(SYS_fstat, fd, info);
}

ssize_t read(int fd, void *buffer, size_t count) {
    if (root && !strcmp(mode, "queue_reader_read") && enabled() && queue_reader(fd)) {
        record("reader_read_eio\n");
        errno = EIO;
        return -1;
    }
    return next_read ? next_read(fd, buffer, count) : syscall(SYS_read, fd, buffer, count);
}

ssize_t write(int fd, const void *buffer, size_t count) {
    enum file_kind target = kind(fd);
    if (enabled() && ((target == QUEUE_DATA &&
        (!strcmp(mode, "queue_enospc") || !strcmp(mode, "queue_short_write"))) ||
        (target == CHECKPOINT && !strcmp(mode, "checkpoint_write")) ||
        (target == RAW && (!strcmp(mode, "raw_enospc") || !strcmp(mode, "raw_short_write"))))) {
        if ((strstr(mode, "short_write") != NULL) && count > 1 &&
            !atomic_exchange(&partial_done, 1)) {
            ssize_t written = next_write(fd, buffer, count / 2);
            if (written > 0) record("partial_write\n");
            return written;
        }
        record("write_enospc\n");
        errno = ENOSPC;
        return -1;
    }
    return next_write(fd, buffer, count);
}

static int sync_fault(int fd) {
    enum file_kind target = kind(fd);
    if (enabled() && ((target == QUEUE_DATA && !strcmp(mode, "queue_sync")) ||
                      (target == RAW && !strcmp(mode, "raw_sync")) ||
                      (target == CHECKPOINT && !strcmp(mode, "checkpoint_sync")) ||
                      (target == QUEUE_DIRECTORY && atomic_load(&checkpoint_renamed) &&
                       !strcmp(mode, "checkpoint_directory_sync")))) {
        record("sync_eio\n");
        errno = EIO;
        return 1;
    }
    return 0;
}

int fdatasync(int fd) { return sync_fault(fd) ? -1 : next_fdatasync(fd); }
int fsync(int fd) { return sync_fault(fd) ? -1 : next_fsync(fd); }

int rename(const char *old_path, const char *new_path) {
    int checkpoint = root && !strncmp(old_path, root, strlen(root)) &&
        !strcmp(old_path + strlen(root), "/queue/fg-receive.qi.tmp") &&
        !strncmp(new_path, root, strlen(root)) &&
        !strcmp(new_path + strlen(root), "/queue/fg-receive.qi");
    if (checkpoint && enabled() && !strcmp(mode, "checkpoint_rename")) {
        record("rename_eio\n");
        errno = EIO;
        return -1;
    }
    int result = next_rename(old_path, new_path);
    if (checkpoint && result == 0) atomic_store(&checkpoint_renamed, 1);
    return result;
}

static int first_spool_file(const char *path) {
    return root && !strncmp(path, root, strlen(root)) &&
        !strcmp(path + strlen(root), "/queue/fg-receive.00000001");
}

int stat(const char *path, struct stat *info) {
    if (atomic_load(&rotation_seen) && first_spool_file(path) && enabled() &&
        !strcmp(mode, "queue_rollover_stat")) {
        record("rollover_stat_eio\n");
        errno = EIO;
        return -1;
    }
    return next_stat ? next_stat(path, info) : syscall(SYS_newfstatat, AT_FDCWD, path, info, 0);
}

int unlink(const char *path) {
    if (atomic_load(&rotation_seen) && first_spool_file(path) && enabled() &&
        !strcmp(mode, "queue_rollover_unlink")) {
        record("rollover_unlink_eio\n");
        errno = EIO;
        return -1;
    }
    return next_unlink ? next_unlink(path) : syscall(SYS_unlinkat, AT_FDCWD, path, 0);
}
