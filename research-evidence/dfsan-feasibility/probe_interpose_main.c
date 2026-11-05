#include <pthread.h>
#include <sanitizer/dfsan_interface.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int sockets[2];

static int handle_request(const char *bytes) {
    fprintf(stderr, "HANDLER_LABEL=%u\n", (unsigned)dfsan_get_label(bytes[0]));
    return bytes[0] == 'X';
}

static void *worker(void *unused) {
    (void)unused;
    char bytes[8] = {0};
#ifdef USE_READ
    ssize_t count = read(sockets[1], bytes, sizeof(bytes));
#else
    ssize_t count = recv(sockets[1], bytes, sizeof(bytes), 0);
#endif
    return (void *)(long)(count > 0 ? handle_request(bytes) : -1);
}

int main(void) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets)) return 2;
    pthread_t thread;
    if (pthread_create(&thread, 0, worker, 0)) return 3;
    if (send(sockets[0], "X", 1, 0) != 1) return 4;
    void *result = 0;
    if (pthread_join(thread, &result)) return 5;
    printf("RESULT=%ld\n", (long)result);
    return 0;
}
