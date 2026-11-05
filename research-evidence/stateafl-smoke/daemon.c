#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int port = atoi(argv[1]);
    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) return 3;
    int reuse = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)port);
    if (bind(server, (struct sockaddr *)&addr, sizeof(addr)) != 0) return 4;
    if (listen(server, 8) != 0) return 5;
    for (;;) {
        int client = accept(server, NULL, NULL);
        if (client < 0) continue;
        int has_item = 0;
        char buf[128];
        ssize_t size;
        while ((size = recv(client, buf, sizeof(buf), 0)) > 0) {
            const char *response = "ERROR\n";
            if (size == 6 && memcmp(buf, "SET a\n", 6) == 0) {
                has_item = 1;
                response = "STORED\n";
            } else if (size == 6 && memcmp(buf, "GET a\n", 6) == 0) {
                response = has_item ? "VALUE\n" : "MISS\n";
            }
            send(client, response, strlen(response), 0);
        }
        close(client);
    }
}
