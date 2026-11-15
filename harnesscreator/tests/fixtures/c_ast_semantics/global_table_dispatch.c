#include <stddef.h>

typedef int (*handler_t)(const unsigned char *, size_t);
static int do_set(const unsigned char *p, size_t n) { return n ? p[0] : 0; }
static int do_get(const unsigned char *p, size_t n) { return n ? -p[0] : 0; }
static handler_t handlers[] = {do_set, do_get};
static int read_request(const unsigned char *p, size_t n) {
    return n ? p[0] : -1;
}
static int select_handler(int selected) { return selected; }

int dispatch(const unsigned char *p, size_t n) {
    int selected = read_request(p, n);
    if (selected < 0 || selected > 1) return 0;
    return handlers[select_handler(selected)](p, n);
}
