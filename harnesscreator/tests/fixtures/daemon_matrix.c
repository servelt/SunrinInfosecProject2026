/* Real C protocol fixtures. No source request sample is passed to the analyzer. */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef HC_ENTRY_ID
#define HC_ENTRY_ID "__ENTRY__"
#endif
#ifndef HC_HANDLER_ID
#define HC_HANDLER_ID "__HANDLER__"
#endif

static void record(const char *kind, const char *request_id,
                   const char *connection_id, const unsigned char *input,
                   size_t size) {
    const char *path = getenv("HARNESSCREATOR_TRACE_JSONL");
    if (!path) return;
    FILE *f = fopen(path, "a");
    if (!f) return;
    if (!strcmp(kind, "acquire")) {
        unsigned char sum[SHA256_DIGEST_LENGTH];
        char hex[65];
        SHA256(input, size, sum);
        for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i)
            snprintf(hex + i * 2, 3, "%02x", sum[i]);
        fprintf(f, "{\"event\":\"acquire\",\"request_id\":\"%s\",\"connection_id\":\"%s\",\"entry_function_id\":\"%s\",\"request_sha256\":\"%s\"}\n",
                request_id, connection_id, HC_ENTRY_ID, hex);
    } else if (!strcmp(kind, "result")) {
        unsigned char sum[SHA256_DIGEST_LENGTH];
        char hex[65];
        SHA256(input, size, sum);
        for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i)
            snprintf(hex + i * 2, 3, "%02x", sum[i]);
        fprintf(f, "{\"event\":\"result\",\"request_id\":\"%s\",\"connection_id\":\"%s\",\"response_sha256\":\"%s\",\"state_digest\":\"6b9d7a02e6f588d275eb4f4f94f48d08983967d0d6d8bd6bc63089d5fd71a502\"}\n",
                request_id, connection_id, hex);
    } else {
        fprintf(f, "{\"event\":\"handler\",\"request_id\":\"%s\",\"connection_id\":\"%s\",\"handler_function_id\":\"%s\"}\n",
                request_id, connection_id, HC_HANDLER_ID);
    }
    fclose(f);
}

static ssize_t input_read(int fd, unsigned char *buf, size_t cap, int datagram,
                          struct sockaddr_in *peer, socklen_t *len) {
    if (datagram) return recvfrom(fd, buf, cap, 0, (struct sockaddr *)peer, len);
    return recv(fd, buf, cap, 0);
}

static const char *target_handler(const unsigned char *buf, size_t size,
                                  const char *request_id, const char *connection_id) {
    if (size == 6 && !memcmp(buf, "HELLO\n", 6)) {
        record("handler", request_id, connection_id, buf, size);
        return "OK\n";
    }
    return "ERR\n";
}

static void process_one(int fd, int datagram) {
    unsigned char buf[512];
    struct sockaddr_in peer = {0};
    socklen_t length = sizeof(peer);
    ssize_t size = input_read(fd, buf, sizeof(buf), datagram, &peer, &length);
    if (size <= 0) return;
    /* The input is handed off across a worker queue in the TCP path. */
    record("acquire", "request-1", "connection-1", buf, (size_t)size);
    const char *response = target_handler(buf, (size_t)size, "request-1", "connection-1");
    if (!strcmp(response, "OK\n"))
        record("result", "request-1", "connection-1",
               (const unsigned char *)response, strlen(response));
    if (datagram) sendto(fd, response, strlen(response), 0, (struct sockaddr *)&peer, length);
    else send(fd, response, strlen(response), 0);
}

static int queue_pipe[2];
static void *worker_thread(void *unused) {
    (void)unused;
    int client = -1;
    if (read(queue_pipe[0], &client, sizeof(client)) == sizeof(client)) {
        process_one(client, 0);
        close(client);
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    int datagram = !strcmp(argv[1], "udp");
    int unix_stream = !strcmp(argv[1], "unix_stream");
    int sock = socket(unix_stream ? AF_UNIX : AF_INET,
                      datagram ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (sock < 0) return 3;
    if (unix_stream) {
        struct sockaddr_un address = {0};
        address.sun_family = AF_UNIX;
        if (strlen(argv[2]) >= sizeof(address.sun_path)) return 4;
        strcpy(address.sun_path, argv[2]);
        if (bind(sock, (struct sockaddr *)&address, sizeof(address)) < 0) return 4;
    } else {
        int reuse = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        struct sockaddr_in address = {0};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons((unsigned short)atoi(argv[2]));
        if (bind(sock, (struct sockaddr *)&address, sizeof(address)) < 0) return 4;
    }
    if (datagram) process_one(sock, 1);
    else {
        if (listen(sock, 1) < 0 || pipe(queue_pipe) != 0) return 5;
        pthread_t worker;
        if (pthread_create(&worker, NULL, worker_thread, NULL) != 0) return 6;
        int fd = accept(sock, NULL, NULL);
        if (fd >= 0) write(queue_pipe[1], &fd, sizeof(fd));
        else { close(queue_pipe[1]); }
        pthread_join(worker, NULL);
        close(queue_pipe[0]);
        close(queue_pipe[1]);
    }
    close(sock);
    if (unix_stream) unlink(argv[2]);
    return 0;
}
