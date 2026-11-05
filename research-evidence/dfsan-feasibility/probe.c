#include <sanitizer/dfsan_interface.h>
#include <stdio.h>
#include <unistd.h>

struct request {
    char bytes[4];
};

static unsigned tainted_conditions;

static void on_tainted_condition(dfsan_label label, dfsan_origin origin) {
    (void)origin;
    if (label != 0) {
        tainted_conditions++;
    }
}

static int process_request(struct request *request, int unrelated_setting) {
    volatile char observed = request->bytes[0];
    (void)observed;
#ifdef UNRELATED_CONDITION_ONLY
    if (unrelated_setting) {
        return 1;
    }
#else
    if (request->bytes[0] == 'A') {
        return 1;
    }
#endif
    return 0;
}

int main(void) {
    struct request request = {{0}};
    dfsan_set_conditional_callback(on_tainted_condition);
    ssize_t count = read(STDIN_FILENO, request.bytes, sizeof(request.bytes));
    if (count <= 0) {
        return 2;
    }
    /* A real adapter would have to label the selected acquisition call. */
    dfsan_set_label(1, request.bytes, (size_t)count);
    int (*callback)(struct request *, int) = process_request;
    int result = callback(&request, 1);
    printf("result=%d tainted_conditions=%u\n", result, tainted_conditions);
    return 0;
}
