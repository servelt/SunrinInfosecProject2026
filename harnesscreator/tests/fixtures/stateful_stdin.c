#define _POSIX_C_SOURCE 200809L
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char saved_key[32];
static int stored = 0;

static void trace_event(const char *kind, int count, const char *handler,
                        const char *input, size_t size) {
    const char *path = getenv("HARNESSCREATOR_TRACE_JSONL");
    if (!path) return;
    FILE *out = fopen(path, "a");
    if (!out) return;
    if (!strcmp(kind, "acquire")) {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        char hex[65];
        SHA256((const unsigned char *)input, size, digest);
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            snprintf(hex + 2 * i, 3, "%02x", digest[i]);
        fprintf(out, "{\"event\":\"acquire\",\"request_id\":\"r-%d\",\"connection_id\":\"stdin\",\"entry_function_id\":\"__ENTRY__\",\"request_sha256\":\"%s\"}\n", count, hex);
    } else if (!strcmp(kind, "result")) {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        unsigned char state_digest[SHA256_DIGEST_LENGTH];
        char state[64];
        char hex[65];
        char state_hex[65];
        SHA256((const unsigned char *)input, size, digest);
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            snprintf(hex + 2 * i, 3, "%02x", digest[i]);
        int state_size = snprintf(state, sizeof(state), "%d:%s", stored, saved_key);
        SHA256((const unsigned char *)state, (size_t)state_size, state_digest);
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            snprintf(state_hex + 2 * i, 3, "%02x", state_digest[i]);
        fprintf(out, "{\"event\":\"result\",\"request_id\":\"r-%d\",\"connection_id\":\"stdin\",\"response_sha256\":\"%s\",\"state_digest\":\"%s\"}\n", count, hex, state_hex);
    } else {
        fprintf(out, "{\"event\":\"handler\",\"request_id\":\"r-%d\",\"connection_id\":\"stdin\",\"handler_function_id\":\"%s\"}\n", count, handler);
    }
    fclose(out);
}

static void handle_set(char *input, int count) {
    char key[32];
    if (sscanf(input, "SET %31s", key) == 1) {
        snprintf(saved_key, sizeof(saved_key), "%s", key);
        stored = 1;
        trace_event("handler", count, "__SET__", input, strlen(input));
        trace_event("result", count, NULL, "OK\n", 3);
        puts("OK");
    } else puts("ERR");
}

static void handle_get(char *input, int count) {
    char key[32];
    if (sscanf(input, "GET %31s", key) == 1 && stored && !strcmp(saved_key, key)) {
        trace_event("handler", count, "__GET__", input, strlen(input));
        trace_event("result", count, NULL, "VALUE:yes\n", 10);
        puts("VALUE:yes");
    } else puts("ERR");
}

static int input_read(char *buffer, size_t capacity) {
    if (!fgets(buffer, (int)capacity, stdin)) return -1;
    return (int)strlen(buffer);
}

int main(void) {
    char buffer[256];
    int count = 0, size;
    while ((size = input_read(buffer, sizeof(buffer))) > 0 && ++count < 4) {
        trace_event("acquire", count, NULL, buffer, (size_t)size);
        if (!strncmp(buffer, "SET ", 4)) handle_set(buffer, count);
        else if (!strncmp(buffer, "GET ", 4)) handle_get(buffer, count);
        else puts("ERR");
        fflush(stdout);
    }
    return 0;
}
