#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Research probe: one recv-to-send window on one thread and one socket. */
static __thread int active_fd = -1;
static __thread unsigned long request_number;
static __thread unsigned acquisition_depth;
static __thread unsigned fragments;
static __thread size_t acquired_bytes;

static int named_function(void *address, const char *environment_name) {
    const char *expected = getenv(environment_name);
    if (!expected || !*expected) return 0;
    Dl_info symbol;
    return dladdr(address, &symbol) && symbol.dli_sname &&
           strcmp(symbol.dli_sname, expected) == 0;
}

static void log_bytes(const char *kind, int fd, const void *data, size_t length) {
    const unsigned char *bytes = data;
    fprintf(stderr, "HC_SCOPE %s tid=%ld fd=%d request=%lu bytes=", kind,
            (long)syscall(SYS_gettid), fd, request_number);
    for (size_t i = 0; i < length && i < 64; ++i)
        fprintf(stderr, "%02x", bytes[i]);
    if (length > 64) fprintf(stderr, "...");
    fprintf(stderr, "\n");
}

void __cyg_profile_func_enter(void *this_fn, void *call_site) {
    (void)call_site;
    if (named_function(this_fn, "HC_ACQUISITION_FUNCTION")) {
        if (acquisition_depth++ == 0) {
            ++request_number;
            fragments = 0;
            acquired_bytes = 0;
            active_fd = -1;
            fprintf(stderr, "HC_SCOPE ACQUIRE_BEGIN tid=%ld request=%lu\n",
                    (long)syscall(SYS_gettid), request_number);
        }
    }
    if (active_fd < 0) return;
    if (named_function(this_fn, "HC_TARGET_FUNCTION")) {
        Dl_info symbol;
        dladdr(this_fn, &symbol);
        fprintf(stderr, "HC_SCOPE ENTER tid=%ld fd=%d request=%lu function=%s\n",
                (long)syscall(SYS_gettid), active_fd, request_number,
                symbol.dli_sname);
    }
}

void __cyg_profile_func_exit(void *this_fn, void *call_site) {
    (void)call_site;
    if (named_function(this_fn, "HC_ACQUISITION_FUNCTION") &&
        acquisition_depth && --acquisition_depth == 0)
        fprintf(stderr,
                "HC_SCOPE ACQUIRE_END tid=%ld fd=%d request=%lu fragments=%u total=%zu\n",
                (long)syscall(SYS_gettid), active_fd, request_number,
                fragments, acquired_bytes);
}

ssize_t recv(int fd, void *buffer, size_t length, int flags) {
    static ssize_t (*next_recv)(int, void *, size_t, int);
    if (!next_recv) next_recv = dlsym(RTLD_NEXT, "recv");
    if (!next_recv) return -1;
    ssize_t count = next_recv(fd, buffer, length, flags);
    if (count > 0) {
        active_fd = fd;
        if (!getenv("HC_ACQUISITION_FUNCTION")) ++request_number;
        if (acquisition_depth) {
            ++fragments;
            acquired_bytes += (size_t)count;
        }
        log_bytes("RECV", fd, buffer, (size_t)count);
    }
    return count;
}

ssize_t send(int fd, const void *buffer, size_t length, int flags) {
    static ssize_t (*next_send)(int, const void *, size_t, int);
    if (!next_send) next_send = dlsym(RTLD_NEXT, "send");
    if (!next_send) return -1;
    if (active_fd == fd)
        log_bytes("SEND", fd, buffer, length);
    ssize_t count = next_send(fd, buffer, length, flags);
    if (active_fd == fd) active_fd = -1;
    return count;
}
