#include <sys/socket.h>
#include <stddef.h>
#define TAKE_PACKET(fd,buf,sz) recv((fd),(buf),(sz),0)
static int handle(const unsigned char *p, size_t n) { return n && p[0]=='A'; }
int read_request(int fd) {
    unsigned char buf[256];
    long got = TAKE_PACKET(fd, buf, sizeof(buf));
    return got > 0 ? handle(buf,(size_t)got) : 0;
}
int main(void) { return 0; }
