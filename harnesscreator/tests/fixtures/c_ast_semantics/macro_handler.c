#include <sys/socket.h>
#include <stddef.h>
#define MAKE_HANDLER(name) static int name(const unsigned char *p, size_t n) { return n && p[0]=='H'; }
MAKE_HANDLER(do_special)
int dispatch(const unsigned char *p, size_t n) { return do_special(p,n); }
int read_request(int fd) {
    unsigned char buf[256];
    long got = recv(fd, buf, sizeof(buf), 0);
    return got > 0 ? dispatch(buf, (size_t)got) : 0;
}
int main(void) { return 0; }
