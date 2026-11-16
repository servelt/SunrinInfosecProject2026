#include <sys/socket.h>
#include <stddef.h>
#include <string.h>
static int do_set(const unsigned char *p, size_t n) { return n && p[0]=='S'; }
static int do_get(const unsigned char *p, size_t n) { return n && p[0]=='G'; }
int dispatch(const unsigned char *p, size_t n) {
    if (n && p[0]=='S') return do_set(p,n);
    if (n && p[0]=='G') return do_get(p,n);
    return 0;
}
int read_request(int fd) {
    unsigned char buf[256];
    long got = recv(fd, buf, sizeof(buf), 0);
    return got > 0 ? dispatch(buf, (size_t)got) : 0;
}
int main(void) { return 0; }
