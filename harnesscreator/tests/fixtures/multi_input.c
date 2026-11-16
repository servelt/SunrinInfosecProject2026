/* Multi-surface C fixture: the input is not always stdin or a socket. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int accept_request(const char *s) {
    return strcmp(s, "HELLO") == 0;
}

const char *load_environment(void) {
    return getenv("HC_INPUT");
}

const char *load_argv(const char *argument) {
    return argument;
}

int load_file(const char *path, char *buf, size_t size) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return -1;
    size_t n = fread(buf, 1, size-1, f);
    fclose(f);
    buf[n] = '\0';
    return (int)n;
}

int main(int argc, char **argv) {
    char buffer[128] = {0};
    const char *input = NULL;
    if (argc < 2) return 2;
    if (strcmp(argv[1], "file") == 0 && argc == 3) {
        if (load_file(argv[2], buffer, sizeof(buffer)) < 0) return 3;
        input = buffer;
    } else if (strcmp(argv[1], "argv") == 0 && argc == 3) {
        input = load_argv(argv[2]);
    } else if (strcmp(argv[1], "env") == 0) {
        input = load_environment();
    }
    if (!input) return 4;
    puts(accept_request(input) ? "OK" : "ERR");
    return 0;
}
