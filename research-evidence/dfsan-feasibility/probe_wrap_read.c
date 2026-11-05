#include <sanitizer/dfsan_interface.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>

/* LLVM's documented custom-wrapper ABI adds one label per argument and a
 * return-label pointer. The linker redirects instrumented read call sites
 * here, then the runtime's existing wrapper runs before we label the bytes. */
ssize_t __real___dfsw_read(int fd, void *buffer, size_t size,
                          dfsan_label fd_label, dfsan_label buffer_label,
                          dfsan_label size_label, dfsan_label *return_label);

ssize_t __wrap___dfsw_read(int fd, void *buffer, size_t size,
                          dfsan_label fd_label, dfsan_label buffer_label,
                          dfsan_label size_label, dfsan_label *return_label) {
    ssize_t count = __real___dfsw_read(
        fd, buffer, size, fd_label, buffer_label, size_label, return_label
    );
    int kind = 0;
    socklen_t length = sizeof(kind);
    if (count > 0 && getsockopt(fd, SOL_SOCKET, SO_TYPE, &kind, &length) == 0) {
        dfsan_set_label(1, buffer, (size_t)count);
        fprintf(stderr, "WRAPPED_READ count=%ld\n", (long)count);
    }
    return count;
}
