#include <pthread.h>
#include <sanitizer/dfsan_interface.h>
#include <stdio.h>

static unsigned char input[8];
static int reached;

static int handle(const unsigned char *data) {
    dfsan_label label = dfsan_get_label(data[0]);
    if (label & 1) reached = 1;
    fprintf(stderr, "TRACE function=handle label=%u\n", (unsigned)label);
    return data[0] == 'X';
}

static void *worker(void *unused) {
    (void)unused;
    return (void *)(long)handle(input);
}

int main(void) {
    if (fread(input, 1, 1, stdin) != 1) return 2;
#ifdef LABEL_INPUT
    dfsan_set_label(1, input, 1);
#endif
    pthread_t thread;
    if (pthread_create(&thread, 0, worker, 0)) return 3;
    void *result = 0;
    if (pthread_join(thread, &result)) return 4;
    printf("RESULT=%ld REACHED=%d\n", (long)result, reached);
    return 0;
}
