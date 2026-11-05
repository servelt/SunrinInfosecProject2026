#define _GNU_SOURCE
#include <dlfcn.h>
#include <sanitizer/dfsan_interface.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef ssize_t (*recv_fn)(int, void *, size_t, int);
typedef ssize_t (*read_fn)(int, void *, size_t);

static int is_socket(int fd) {
    int kind = 0;
    socklen_t length = sizeof(kind);
    return getsockopt(fd, SOL_SOCKET, SO_TYPE, &kind, &length) == 0;
}

static void on_reach(dfsan_label label, dfsan_origin origin,
                     const char *file, unsigned line, const char *function) {
    (void)origin;
    (void)file;
    (void)line;
    const char *target = getenv("HC_TRACE_FUNCTION_SUBSTR");
    if (!target || !*target) target = "handle_request";
    if (label && function && strstr(function, target))
        fprintf(stderr, "REACH %s label=%u\n", function, (unsigned)label);
}

static void on_condition(dfsan_label label, dfsan_origin origin) {
    (void)origin;
    static int count;
    if (label && count++ < 100)
        fprintf(stderr, "CONDITION label=%u pc=%p\n", (unsigned)label,
                __builtin_return_address(0));
}

__attribute__((constructor)) static void trace_start(void) {
    dfsan_set_reaches_function_callback(on_reach);
    if (getenv("HC_TRACE_CONDITIONS"))
        dfsan_set_conditional_callback(on_condition);
}

ssize_t recv(int fd, void *buffer, size_t length, int flags) {
    static recv_fn next_recv;
    if (!next_recv) next_recv = (recv_fn)dlsym(RTLD_NEXT, "recv");
    if (!next_recv) return -1;
    ssize_t count = next_recv(fd, buffer, length, flags);
    if (count > 0 && is_socket(fd)) {
        if (!getenv("HC_DISABLE_LABEL"))
            dfsan_set_label(1, buffer, (size_t)count);
        if (getenv("HC_TRACE_ACQUIRE"))
            fprintf(stderr, "ACQUIRE recv fd=%d count=%ld\n", fd, (long)count);
    }
    return count;
}

ssize_t read(int fd, void *buffer, size_t length) {
    static read_fn next_read;
    if (!next_read) next_read = (read_fn)dlsym(RTLD_NEXT, "read");
    if (!next_read) return -1;
    ssize_t count = next_read(fd, buffer, length);
    if (count > 0 && is_socket(fd)) {
        if (!getenv("HC_DISABLE_LABEL"))
            dfsan_set_label(1, buffer, (size_t)count);
        if (getenv("HC_TRACE_ACQUIRE"))
            fprintf(stderr, "ACQUIRE read fd=%d count=%ld\n", fd, (long)count);
    }
    return count;
}
