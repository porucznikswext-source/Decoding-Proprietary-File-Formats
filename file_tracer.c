#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>

#define MAX_TARGET_LEN 256
#define MAX_DUMP_BYTES 32
#define MAX_FDS 1024

/* Internal state structure for tracked file descriptors */
typedef struct {
    bool tracked;
    int64_t current_offset;
    char filepath[MAX_TARGET_LEN];
} fd_state_t;

static fd_state_t g_fd_table[MAX_FDS];
static char g_target_match[MAX_TARGET_LEN] = {0};
static int g_log_fd = -1;
static bool g_initialized = false;

/* Original libc function pointers */
static int (*real_open)(const char *pathname, int flags, ...) = NULL;
static int (*real_openat)(int dirfd, const char *pathname, int flags, ...) = NULL;
static int (*real_creat)(const char *pathname, mode_t mode) = NULL;
static ssize_t (*real_write)(int fd, const void *buf, size_t count) = NULL;
static ssize_t (*real_pwrite64)(int fd, const void *buf, size_t count, off64_t offset) = NULL;
static off_t (*real_lseek)(int fd, off_t offset, int whence) = NULL;
static off64_t (*real_lseek64)(int fd, off64_t offset, int whence) = NULL;
static int (*real_close)(int fd) = NULL;

/* Initialize function pointers using runtime dynamic linker interposition */
static void initialize_interceptor(void) {
    if (g_initialized) {
        return;
    }

    real_open = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open");
    real_openat = (int (*)(int, const char *, int, ...))dlsym(RTLD_NEXT, "openat");
    real_creat = (int (*)(const char *, mode_t))dlsym(RTLD_NEXT, "creat");
    real_write = (ssize_t (*)(int, const void *, size_t))dlsym(RTLD_NEXT, "write");
    real_pwrite64 = (ssize_t (*)(int, const void *, size_t, off64_t))dlsym(RTLD_NEXT, "pwrite64");
    real_lseek = (off_t (*)(int, off_t, int))dlsym(RTLD_NEXT, "lseek");
    real_lseek64 = (off64_t (*)(int, off64_t, int))dlsym(RTLD_NEXT, "lseek64");
    real_close = (int (*)(int))dlsym(RTLD_NEXT, "close");

    if (!real_open || !real_write || !real_close) {
        const char *err = "[-] Fatal: Failed to resolve libc entrypoints.\n";
        (void)!write(STDERR_FILENO, err, strlen(err));
        exit(EXIT_FAILURE);
    }

    const char *target = getenv("TRACE_TARGET");
    if (target != NULL && strlen(target) > 0) {
        strncpy(g_target_match, target, sizeof(g_target_match) - 1);
    } else {
        g_target_match[0] = '\0';
    }

    const char *logfile = getenv("TRACE_OUTPUT");
    if (logfile != NULL && strlen(logfile) > 0) {
        g_log_fd = real_open(logfile, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    } else {
        g_log_fd = STDERR_FILENO;
    }

    for (int i = 0; i < MAX_FDS; i++) {
        g_fd_table[i].tracked = false;
        g_fd_table[i].current_offset = 0;
        g_fd_table[i].filepath[0] = '\0';
    }

    g_initialized = true;
}

/* Helper to convert raw binary memory into an uppercase hex string */
static void bytes_to_hex(const uint8_t *src, size_t len, char *dest, size_t dest_max) {
    static const char hex_digits[] = "0123456789ABCDEF";
    size_t out_idx = 0;
    for (size_t i = 0; i < len && (out_idx + 3) < dest_max; i++) {
        dest[out_idx++] = hex_digits[(src[i] >> 4) & 0x0F];
        dest[out_idx++] = hex_digits[src[i] & 0x0F];
        if (i + 1 < len) {
            dest[out_idx++] = ' ';
        }
    }
    dest[out_idx] = '\0';
}

/* Emit structured JSONL log entries using only direct libc write calls */
static void emit_log(const char *op, int fd, int64_t offset, int64_t len, 
                     const char *extra, const uint8_t *data, size_t data_len) {
    if (g_log_fd < 0) return;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    char hex_dump[MAX_DUMP_BYTES * 3 + 1] = {0};
    if (data != NULL && data_len > 0) {
        size_t dump_count = (data_len > MAX_DUMP_BYTES) ? MAX_DUMP_BYTES : data_len;
        bytes_to_hex(data, dump_count, hex_dump, sizeof(hex_dump));
    }

    char buffer[1024];
    int written = snprintf(
        buffer, sizeof(buffer),
        "{\"ts\":%ld.%09ld,\"fd\":%d,\"op\":\"%s\",\"off\":%ld,\"len\":%ld,"
        "\"file\":\"%s\",\"extra\":\"%s\",\"bytes\":\"%s\"}\n",
        ts.tv_sec, ts.tv_nsec, fd, op, (long)offset, (long)len,
        g_fd_table[fd].filepath, extra ? extra : "", hex_dump
    );

    if (written > 0) {
        (void)!real_write(g_log_fd, buffer, (size_t)written);
    }
}

/* Check if a file should be tracked based on configuration */
static bool should_track_path(const char *pathname) {
    if (!pathname) return false;
    if (g_target_match[0] == '\0') return true;
    return (strstr(pathname, g_target_match) != NULL);
}

int open(const char *pathname, int flags, ...) {
    initialize_interceptor();
    mode_t mode = 0;
    if (__OPEN_NEEDS_MODE(flags)) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, mode_t);
        va_end(args);
    }

    int fd = real_open(pathname, flags, mode);
    if (fd >= 0 && fd < MAX_FDS) {
        if (should_track_path(pathname)) {
            g_fd_table[fd].tracked = true;
            g_fd_table[fd].current_offset = (flags & O_APPEND) ? 
                real_lseek(fd, 0, SEEK_END) : 0;
            strncpy(g_fd_table[fd].filepath, pathname, MAX_TARGET_LEN - 1);
            emit_log("OPEN", fd, g_fd_table[fd].current_offset, 0, "open", NULL, 0);
        } else {
            g_fd_table[fd].tracked = false;
        }
    }
    return fd;
}

int openat(int dirfd, const char *pathname, int flags, ...) {
    initialize_interceptor();
    mode_t mode = 0;
    if (__OPEN_NEEDS_MODE(flags)) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, mode_t);
        va_end(args);
    }

    int fd = real_openat(dirfd, pathname, flags, mode);
    if (fd >= 0 && fd < MAX_FDS) {
        if (should_track_path(pathname)) {
            g_fd_table[fd].tracked = true;
            g_fd_table[fd].current_offset = (flags & O_APPEND) ? 
                real_lseek(fd, 0, SEEK_END) : 0;
            strncpy(g_fd_table[fd].filepath, pathname, MAX_TARGET_LEN - 1);
            emit_log("OPEN", fd, g_fd_table[fd].current_offset, 0, "openat", NULL, 0);
        } else {
            g_fd_table[fd].tracked = false;
        }
    }
    return fd;
}

int creat(const char *pathname, mode_t mode) {
    initialize_interceptor();
    int fd = real_creat(pathname, mode);
    if (fd >= 0 && fd < MAX_FDS) {
        if (should_track_path(pathname)) {
            g_fd_table[fd].tracked = true;
            g_fd_table[fd].current_offset = 0;
            strncpy(g_fd_table[fd].filepath, pathname, MAX_TARGET_LEN - 1);
            emit_log("OPEN", fd, 0, 0, "creat", NULL, 0);
        } else {
            g_fd_table[fd].tracked = false;
        }
    }
    return fd;
}

ssize_t write(int fd, const void *buf, size_t count) {
    initialize_interceptor();
    if (fd >= 0 && fd < MAX_FDS && g_fd_table[fd].tracked) {
        int64_t target_offset = g_fd_table[fd].current_offset;
        ssize_t res = real_write(fd, buf, count);
        if (res > 0) {
            emit_log("WRITE", fd, target_offset, res, "seq", (const uint8_t *)buf, res);
            g_fd_table[fd].current_offset += res;
        }
        return res;
    }
    return real_write(fd, buf, count);
}

ssize_t pwrite64(int fd, const void *buf, size_t count, off64_t offset) {
    initialize_interceptor();
    if (fd >= 0 && fd < MAX_FDS && g_fd_table[fd].tracked) {
        ssize_t res = real_pwrite64(fd, buf, count, offset);
        if (res > 0) {
            emit_log("PWRITE", fd, (int64_t)offset, res, "direct", 
                     (const uint8_t *)buf, res);
        }
        return res;
    }
    return real_pwrite64(fd, buf, count, offset);
}

off_t lseek(int fd, off_t offset, int whence) {
    initialize_interceptor();
    off_t res = real_lseek(fd, offset, whence);
    if (fd >= 0 && fd < MAX_FDS && g_fd_table[fd].tracked && res != (off_t)-1) {
        int64_t prev = g_fd_table[fd].current_offset;
        g_fd_table[fd].current_offset = (int64_t)res;
        const char *seek_type = (res < prev) ? "BACKPATCH_SEEK" : "FORWARD_SEEK";
        emit_log("LSEEK", fd, (int64_t)res, (int64_t)(res - prev), seek_type, NULL, 0);
    }
    return res;
}

off64_t lseek64(int fd, off64_t offset, int whence) {
    initialize_interceptor();
    off64_t res = real_lseek64(fd, offset, whence);
    if (fd >= 0 && fd < MAX_FDS && g_fd_table[fd].tracked && res != (off64_t)-1) {
        int64_t prev = g_fd_table[fd].current_offset;
        g_fd_table[fd].current_offset = (int64_t)res;
        const char *seek_type = (res < prev) ? "BACKPATCH_SEEK" : "FORWARD_SEEK";
        emit_log("LSEEK", fd, (int64_t)res, (int64_t)(res - prev), seek_type, NULL, 0);
    }
    return res;
}

int close(int fd) {
    initialize_interceptor();
    if (fd >= 0 && fd < MAX_FDS && g_fd_table[fd].tracked) {
        emit_log("CLOSE", fd, g_fd_table[fd].current_offset, 0, "close", NULL, 0);
        g_fd_table[fd].tracked = false;
        g_fd_table[fd].filepath[0] = '\0';
    }
    return real_close(fd);
}
