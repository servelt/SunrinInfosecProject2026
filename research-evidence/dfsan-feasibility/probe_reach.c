#include <sanitizer/dfsan_interface.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct request {
    char bytes[4];
};

static void on_reach(dfsan_label label, dfsan_origin origin,
                     const char *file, unsigned line, const char *function) {
    (void)origin;
    (void)file;
    (void)line;
    if (label && function && strstr(function, "process_request")) {
        fprintf(stderr, "REACH %s label=%u\n", function, label);
    }
}

static int process_request(struct request *request) {
#ifdef UNRELATED_CONDITION_ONLY
    volatile char observed = request->bytes[0];
    (void)observed;
    int unrelated_setting = 1;
    return unrelated_setting ? 1 : 0;
#else
    return request->bytes[0] == 'A';
#endif
}

int main(void) {
    struct request request = {{0}};
    dfsan_set_reaches_function_callback(on_reach);
    ssize_t count = read(STDIN_FILENO, request.bytes, sizeof(request.bytes));
    if (count <= 0) {
        return 2;
    }
    dfsan_set_label(1, request.bytes, (size_t)count);
    int (*callback)(struct request *) = process_request;
    return callback(&request) ? 0 : 1;
}
