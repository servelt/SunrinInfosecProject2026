#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

int handle(const unsigned char *data, size_t size) {
    return size > 0 && data[0] == 'X';
}

int dispatch(const unsigned char *data, size_t size) {
    if (size == 0) return 0;
    switch (data[0]) {
    case 'X':
        return handle(data, size);
    default:
        return 0;
    }
}

int process_once(FILE *input, FILE *output) {
    unsigned char byte = 0;
    if (fread(&byte, 1, 1, input) != 1) return 0;
    if (dispatch(&byte, 1)) {
        fwrite("OK\n", 1, 3, output);
    } else {
        fwrite("ERR\n", 1, 4, output);
    }
    fflush(output);
    return 1;
}

#ifdef __cplusplus
}
#endif

#ifndef HARNESS_BUILD
int main(void) {
    while (process_once(stdin, stdout)) {}
    return 0;
}
#endif
