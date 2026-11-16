#include <sys/socket.h>
#include <stddef.h>
struct Command { unsigned char op; int (*run)(const unsigned char *, size_t); };
static int do_set(const unsigned char *p, size_t n) { return (int)n + (int)p[0]; }
static int do_get(const unsigned char *p, size_t n) { return (int)n - (int)p[0]; }
int dispatch(const unsigned char *p, size_t n) {
    static const struct Command tbl[] = {{'S', do_set}, {'G', do_get}};
    for (size_t i = 0; i < sizeof(tbl)/sizeof(tbl[0]); ++i)
        if (n && tbl[i].op == p[0]) return tbl[i].run(p, n);
    return 0;
}
int read_request(int fd) {
    unsigned char buf[256];
    long got = recv(fd, buf, sizeof(buf), 0);
    return got > 0 ? dispatch(buf, (size_t)got) : 0;
}
int main(void) { return 0; }
