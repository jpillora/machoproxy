// Loaded by dyld into the executable that replaces the Go launcher.
// Calls from this image to the original symbols are not interposed by dyld.
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define INTERPOSE(replacement, original) \
    __attribute__((used)) static const struct { \
        const void *replacement; const void *original; \
    } interpose_##replacement __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(uintptr_t)&replacement, (const void *)(uintptr_t)&original \
    }

static _Atomic int log_fd = -1;
static _Thread_local int logging;

// dyld can invoke hooks before libSystem has initialized TLS. Keep TLS access
// behind a call boundary: clang otherwise hoists its bootstrap before the guard.
__attribute__((noinline)) static int thread_idle(void) { return !logging; }

// One bounded write per record; no stdio buffering or locks held over fork.
// errno must remain exactly what the intercepted call left behind.
__attribute__((format(printf, 1, 2))) static void record(const char *format, ...) {
    int saved = errno;
    if (log_fd < 0 || !thread_idle()) return;
    logging = 1;
    char line[4096];
    struct timespec now = {0};
    uint64_t tid = 0;
    clock_gettime(CLOCK_REALTIME, &now);
    pthread_threadid_np(NULL, &tid);
    int prefix = snprintf(line, sizeof(line), "%lld.%09ld pid=%d tid=%llu ",
        (long long)now.tv_sec, now.tv_nsec, getpid(), (unsigned long long)tid);
    va_list ap;
    va_start(ap, format);
    int length = vsnprintf(line + prefix, sizeof(line) - (size_t)prefix, format, ap);
    va_end(ap);
    size_t used = (size_t)prefix + (length > 0 ? (size_t)length : 0);
    if (used > sizeof(line) - 2) used = sizeof(line) - 2;
    line[used++] = '\n';
    (void)write(log_fd, line, used);
    logging = 0;
    errno = saved;
}

// Reading a bad user pointer must not turn the target's EFAULT into a crash.
static int safe_copy(void *out, const void *address, size_t size) {
    mach_vm_size_t copied = 0;
    return mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)address,
        size, (mach_vm_address_t)out, &copied) == KERN_SUCCESS && copied == size;
}

static const char *path_text(const char *path) {
    static _Thread_local char slots[4][1100];
    static _Thread_local unsigned index;
    char *out = slots[index++ % 4];
    if (!path) return "NULL";
    size_t used = 0;
    out[used++] = '"';
    // Page-bounded copies also work when a string ends at a mapping boundary.
    for (size_t offset = 0; offset < 256;) {
        unsigned char chunk[64];
        uintptr_t address = (uintptr_t)path + offset;
        size_t size = vm_page_size - (address % vm_page_size);
        if (size > sizeof(chunk)) size = sizeof(chunk);
        if (size > 256 - offset) size = 256 - offset;
        if (!safe_copy(chunk, (const void *)address, size)) {
            snprintf(out, 1100, "<unreadable:%p>", (const void *)path);
            return out;
        }
        for (size_t i = 0; i < size; i++) {
            unsigned char c = chunk[i];
            if (c == 0) {
                out[used++] = '"';
                out[used] = 0;
                return out;
            }
            if (c == '"' || c == '\\') {
                out[used++] = '\\'; out[used++] = (char)c;
            } else if (c < 32 || c >= 127) {
                used += (size_t)snprintf(out + used, 1100 - used, "\\x%02x", c);
            } else {
                out[used++] = (char)c;
            }
        }
        offset += size;
    }
    memcpy(out + used, "...\"", 5);
    return out;
}

static const char *address_text(const struct sockaddr *address, socklen_t size) {
    static _Thread_local char out[160];
    struct sockaddr_storage value = {0};
    if (size > sizeof(value)) size = sizeof(value);
    if (size < 2 || !safe_copy(&value, address, size)) {
        snprintf(out, sizeof(out), "%p", (const void *)address);
        return out;
    }
    char ip[INET6_ADDRSTRLEN] = {0};
    if (value.ss_family == AF_INET && size >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *v = (const struct sockaddr_in *)&value;
        inet_ntop(AF_INET, &v->sin_addr, ip, sizeof(ip));
        snprintf(out, sizeof(out), "%s:%u", ip, ntohs(v->sin_port));
    } else if (value.ss_family == AF_INET6 && size >= sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *v = (const struct sockaddr_in6 *)&value;
        inet_ntop(AF_INET6, &v->sin6_addr, ip, sizeof(ip));
        snprintf(out, sizeof(out), "[%s]:%u", ip, ntohs(v->sin6_port));
    } else {
        snprintf(out, sizeof(out), "family=%d,address=%p,len=%u", value.ss_family, (const void *)address, size);
    }
    return out;
}

__attribute__((constructor)) static void loaded(void) {
    int saved = errno;
    const char *fd = getenv("MACHOPROXY_LOG_FD");
    if (fd) {
        char *end = NULL;
        long value = strtol(fd, &end, 10);
        struct stat st;
        if (end != fd && *end == 0 && value >= 0 && value <= INT_MAX &&
            fstat((int)value, &st) == 0 && S_ISREG(st.st_mode)) log_fd = (int)value;
    }
    if (log_fd < 0) {
        const char *path = getenv("MACHOPROXY_LOG");
        if (path) log_fd = open(path, O_WRONLY | O_APPEND | O_NOFOLLOW);
    }
    if (log_fd < 0) {
        const char message[] = "machoproxy: injected library could not open the trace log\n";
        (void)write(STDERR_FILENO, message, sizeof(message) - 1);
    } else {
        record("loaded backend=dyld-interpose coverage=library-calls");
    }
    errno = saved;
}

__attribute__((destructor)) static void unloaded(void) {
    record("unloaded");
}

#define WRAP(type, name, declaration, arguments, format, ...) \
    static type proxy_##name declaration { \
        type result = name arguments; \
        int saved = errno; \
        if (log_fd >= 0 && thread_idle()) record(#name "(" format ") = %lld errno=%d", \
            __VA_ARGS__, (long long)(intptr_t)result, \
            (intptr_t)result == -1 ? saved : 0); \
        errno = saved; \
        return result; \
    } \
    INTERPOSE(proxy_##name, name)

// open's mode is only present with O_CREAT; reading an absent vararg is UB.
#define OPEN_WRAPPER(name) \
    static int proxy_##name(const char *path, int flags, ...) { \
        mode_t mode = 0; \
        if (flags & O_CREAT) { \
            va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap); \
        } \
        int result = name(path, flags, mode); \
        int saved = errno; \
        if (log_fd >= 0 && thread_idle()) record(#name "(%s, flags=0x%x, mode=0%o) = %d errno=%d", \
            path_text(path), flags, mode, result, result == -1 ? saved : 0); \
        errno = saved; \
        return result; \
    } \
    INTERPOSE(proxy_##name, name)

#define OPENAT_WRAPPER(name) \
    static int proxy_##name(int dirfd, const char *path, int flags, ...) { \
        mode_t mode = 0; \
        if (flags & O_CREAT) { \
            va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap); \
        } \
        int result = name(dirfd, path, flags, mode); \
        int saved = errno; \
        if (log_fd >= 0 && thread_idle()) record(#name "(%d, %s, flags=0x%x, mode=0%o) = %d errno=%d", \
            dirfd, path_text(path), flags, mode, result, result == -1 ? saved : 0); \
        errno = saved; \
        return result; \
    } \
    INTERPOSE(proxy_##name, name)

OPEN_WRAPPER(open);
OPENAT_WRAPPER(openat);

// libSystem and Go also use cancellation-free entry points.
extern int open_nocancel(const char *, int, ...) __asm("_open$NOCANCEL");
extern int openat_nocancel(int, const char *, int, ...) __asm("_openat$NOCANCEL");
extern int close_nocancel(int) __asm("_close$NOCANCEL");
extern ssize_t read_nocancel(int, void *, size_t) __asm("_read$NOCANCEL");
extern ssize_t write_nocancel(int, const void *, size_t) __asm("_write$NOCANCEL");
OPEN_WRAPPER(open_nocancel);
OPENAT_WRAPPER(openat_nocancel);

// Don't write to a reused descriptor if the target deliberately closes our log.
#define CLOSE_WRAPPER(name) \
    static int proxy_##name(int fd) { \
        int result = name(fd); \
        int saved = errno; \
        if (fd == log_fd && result == 0) log_fd = -1; \
        if (log_fd >= 0 && thread_idle()) record(#name "(%d) = %d errno=%d", fd, result, result == -1 ? saved : 0); \
        errno = saved; \
        return result; \
    } \
    INTERPOSE(proxy_##name, name)
CLOSE_WRAPPER(close);
CLOSE_WRAPPER(close_nocancel);

WRAP(ssize_t, read, (int fd, void *buf, size_t size), (fd, buf, size), "%d, %p, %zu", fd, buf, size);
WRAP(ssize_t, write, (int fd, const void *buf, size_t size), (fd, buf, size), "%d, %p, %zu", fd, buf, size);
WRAP(ssize_t, read_nocancel, (int fd, void *buf, size_t size), (fd, buf, size), "%d, %p, %zu", fd, buf, size);
WRAP(ssize_t, write_nocancel, (int fd, const void *buf, size_t size), (fd, buf, size), "%d, %p, %zu", fd, buf, size);
WRAP(ssize_t, pread, (int fd, void *buf, size_t size, off_t offset), (fd, buf, size, offset), "%d, %p, %zu, %lld", fd, buf, size, offset);
WRAP(ssize_t, pwrite, (int fd, const void *buf, size_t size, off_t offset), (fd, buf, size, offset), "%d, %p, %zu, %lld", fd, buf, size, offset);
WRAP(ssize_t, readv, (int fd, const struct iovec *iov, int count), (fd, iov, count), "%d, %p, %d", fd, (const void *)iov, count);
WRAP(ssize_t, writev, (int fd, const struct iovec *iov, int count), (fd, iov, count), "%d, %p, %d", fd, (const void *)iov, count);
WRAP(off_t, lseek, (int fd, off_t offset, int whence), (fd, offset, whence), "%d, %lld, %d", fd, offset, whence);
WRAP(int, fsync, (int fd), (fd), "%d", fd);
WRAP(int, ftruncate, (int fd, off_t length), (fd, length), "%d, %lld", fd, length);
WRAP(int, stat, (const char *path, struct stat *buf), (path, buf), "%s, %p", path_text(path), (void *)buf);
WRAP(int, lstat, (const char *path, struct stat *buf), (path, buf), "%s, %p", path_text(path), (void *)buf);
WRAP(int, fstat, (int fd, struct stat *buf), (fd, buf), "%d, %p", fd, (void *)buf);
WRAP(int, access, (const char *path, int mode), (path, mode), "%s, 0x%x", path_text(path), mode);
WRAP(int, unlink, (const char *path), (path), "%s", path_text(path));
WRAP(int, unlinkat, (int fd, const char *path, int flags), (fd, path, flags), "%d, %s, 0x%x", fd, path_text(path), flags);
WRAP(int, rename, (const char *from, const char *to), (from, to), "%s, %s", path_text(from), path_text(to));
WRAP(int, mkdir, (const char *path, mode_t mode), (path, mode), "%s, 0%o", path_text(path), mode);
WRAP(int, rmdir, (const char *path), (path), "%s", path_text(path));
WRAP(int, chdir, (const char *path), (path), "%s", path_text(path));
WRAP(int, fchdir, (int fd), (fd), "%d", fd);
WRAP(ssize_t, readlink, (const char *path, char *buf, size_t size), (path, buf, size), "%s, %p, %zu", path_text(path), (void *)buf, size);
WRAP(int, dup, (int fd), (fd), "%d", fd);
WRAP(int, pipe, (int *fds), (fds), "%p", (void *)fds);
WRAP(int, socket, (int domain, int type, int protocol), (domain, type, protocol), "%d, %d, %d", domain, type, protocol);
WRAP(int, socketpair, (int domain, int type, int protocol, int *fds), (domain, type, protocol, fds), "%d, %d, %d, %p", domain, type, protocol, (void *)fds);
WRAP(int, connect, (int fd, const struct sockaddr *address, socklen_t size), (fd, address, size), "%d, %s, %u", fd, address_text(address, size), size);
WRAP(int, bind, (int fd, const struct sockaddr *address, socklen_t size), (fd, address, size), "%d, %s, %u", fd, address_text(address, size), size);
WRAP(int, listen, (int fd, int backlog), (fd, backlog), "%d, %d", fd, backlog);
WRAP(int, accept, (int fd, struct sockaddr *address, socklen_t *size), (fd, address, size), "%d, %p, %p", fd, (void *)address, (void *)size);
WRAP(ssize_t, send, (int fd, const void *buf, size_t size, int flags), (fd, buf, size, flags), "%d, %p, %zu, 0x%x", fd, buf, size, flags);
WRAP(ssize_t, recv, (int fd, void *buf, size_t size, int flags), (fd, buf, size, flags), "%d, %p, %zu, 0x%x", fd, buf, size, flags);
WRAP(ssize_t, sendto, (int fd, const void *buf, size_t size, int flags, const struct sockaddr *address, socklen_t addrlen), (fd, buf, size, flags, address, addrlen), "%d, %p, %zu, 0x%x, %s, %u", fd, buf, size, flags, address_text(address, addrlen), addrlen);
WRAP(ssize_t, recvfrom, (int fd, void *buf, size_t size, int flags, struct sockaddr *address, socklen_t *addrlen), (fd, buf, size, flags, address, addrlen), "%d, %p, %zu, 0x%x, %p, %p", fd, buf, size, flags, (void *)address, (void *)addrlen);
WRAP(int, shutdown, (int fd, int how), (fd, how), "%d, %d", fd, how);
WRAP(void *, mmap, (void *address, size_t length, int prot, int flags, int fd, off_t offset), (address, length, prot, flags, fd, offset), "%p, %zu, 0x%x, 0x%x, %d, %lld", address, length, prot, flags, fd, offset);
WRAP(int, munmap, (void *address, size_t length), (address, length), "%p, %zu", address, length);
WRAP(int, mprotect, (void *address, size_t length, int prot), (address, length, prot), "%p, %zu, 0x%x", address, length, prot);
WRAP(pid_t, fork, (void), (), "%s", "");
WRAP(int, kill, (pid_t pid, int sig), (pid, sig), "%d, %d", pid, sig);

static int proxy_dup2(int fd, int other) {
    int result = dup2(fd, other);
    int saved = errno;
    if (result >= 0 && fd != other && other == log_fd) log_fd = -1;
    record("dup2(%d, %d) = %d errno=%d", fd, other, result, result == -1 ? saved : 0);
    errno = saved;
    return result;
}
INTERPOSE(proxy_dup2, dup2);

// Successful exec and exit never return, so log these before passing through.
static int proxy_execve(const char *path, char *const argv[], char *const envp[]) {
    int saved = errno;
    if (log_fd >= 0 && thread_idle()) record("execve(%s, argv=%p, envp=%p) enter", path_text(path), (void *)argv, (void *)envp);
    errno = saved;
    int result = execve(path, argv, envp);
    saved = errno;
    record("execve return=%d errno=%d", result, saved);
    errno = saved;
    return result;
}
INTERPOSE(proxy_execve, execve);

#define SPAWN_WRAPPER(name) \
    static int proxy_##name(pid_t *pid, const char *path, \
        const posix_spawn_file_actions_t *actions, const posix_spawnattr_t *attr, \
        char *const argv[], char *const envp[]) { \
        int saved = errno; \
        if (log_fd >= 0 && thread_idle()) record(#name "(%s, argv=%p) enter", path_text(path), (void *)argv); \
        errno = saved; \
        int result = name(pid, path, actions, attr, argv, envp); \
        saved = errno; \
        record(#name " return=%d error=%d", result, result); \
        errno = saved; \
        return result; \
    } \
    INTERPOSE(proxy_##name, name)
SPAWN_WRAPPER(posix_spawn);
SPAWN_WRAPPER(posix_spawnp);

static void proxy_exit(int status) {
    record("exit(%d)", status);
    exit(status);
}
INTERPOSE(proxy_exit, exit);

static void proxy__exit(int status) {
    record("_exit(%d)", status);
    _exit(status);
}
INTERPOSE(proxy__exit, _exit);
