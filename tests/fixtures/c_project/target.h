#include <stddef.h>
#include <stdint.h>

int parse_frame(const uint8_t *data, size_t size);
int serve_client(int fd);
