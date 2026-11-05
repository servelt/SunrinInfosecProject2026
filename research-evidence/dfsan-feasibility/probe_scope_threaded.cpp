#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <thread>

#ifdef HC_DFSAN_DIAG
#include <sanitizer/dfsan_interface.h>
#endif

__attribute__((noinline)) int handle_request(int fd, const char *bytes, size_t size) {
#ifdef HC_DFSAN_DIAG
    std::fprintf(stderr, "HANDLER_LABEL=%u\n",
                 static_cast<unsigned>(dfsan_read_label(bytes, size)));
#endif
#ifdef HC_INLINE_COMPARE
    bool matches = size == 5;
    for (size_t i = 0; i < 5 && matches; ++i)
        matches = bytes[i] == "HELLO"[i];
    const char *reply = matches ? "OK\n" : "ERR\n";
#else
    const char *reply = size == 5 && std::memcmp(bytes, "HELLO", 5) == 0
        ? "OK\n" : "ERR\n";
#endif
    return send(fd, reply, std::strlen(reply), 0) >= 0 ? 0 : 1;
}

int main(int argc, char **argv) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) return 1;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0
        || listen(listener, 1) != 0) return 2;
    socklen_t address_size = sizeof(address);
    if (getsockname(listener, reinterpret_cast<sockaddr *>(&address), &address_size) != 0)
        return 3;
    std::printf("%u\n", static_cast<unsigned>(ntohs(address.sin_port)));
    std::fflush(stdout);
    int client = accept(listener, nullptr, nullptr);
    if (client < 0) return 4;
    char request[64]{};
    ssize_t length = recv(client, request, sizeof(request), 0);
    if (length <= 0) return 5;
    int result = 0;
    if (argc > 1 && std::strcmp(argv[1], "worker") == 0) {
        std::thread worker([&] {
            result = handle_request(client, request, static_cast<size_t>(length));
        });
        worker.join();
    } else {
        result = handle_request(client, request, static_cast<size_t>(length));
    }
    close(client);
    close(listener);
    return result;
}
