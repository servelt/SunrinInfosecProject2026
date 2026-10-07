#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define TRACE_FRAME(value) \
    fprintf(stderr, "frame=%d\n", (value))

int parse_frame(const uint8_t *data, size_t size) {
    if (size < 2) {
        return -1;
    }
    return data[0] == 0x42 ? 0 : 1;
}

int serve_client(int fd) {
    uint8_t buffer[256];
    int received = recv(fd, buffer, sizeof(buffer), 0);
    if (received <= 0) {
        return -1;
    }
    return parse_frame(buffer, (size_t)received);
}
