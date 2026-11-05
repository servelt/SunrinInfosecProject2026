#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

static int requests[2];
static int replies[2];
static pthread_t worker;

static void stop_worker(void) {
  close(requests[1]);
  pthread_join(worker, NULL);
  close(requests[0]);
  close(replies[0]);
  close(replies[1]);
}

static int read_all(int fd, void *buffer, size_t size) {
  unsigned char *p = buffer;
  while (size) {
    ssize_t got = read(fd, p, size);
    if (got <= 0) return -1;
    p += got;
    size -= (size_t)got;
  }
  return 0;
}

static int write_all(int fd, const void *buffer, size_t size) {
  const unsigned char *p = buffer;
  while (size) {
    ssize_t wrote = write(fd, p, size);
    if (wrote <= 0) return -1;
    p += wrote;
    size -= (size_t)wrote;
  }
  return 0;
}

static void *server_loop(void *ignored) {
  (void)ignored;
  for (;;) {
    uint32_t length;
    if (read_all(requests[0], &length, sizeof(length))) return NULL;
    unsigned char checksum = 0;
    for (uint32_t i = 0; i < length; ++i) {
      unsigned char byte;
      if (read_all(requests[0], &byte, 1)) return NULL;
      checksum ^= byte;
    }
    if (write_all(replies[1], &checksum, 1)) return NULL;
  }
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  if (pipe(requests) || pipe(replies) ||
      pthread_create(&worker, NULL, server_loop, NULL)) abort();
  if (atexit(stop_worker)) abort();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 4096) return 0;
  uint32_t length = (uint32_t)size;
  if (write_all(requests[1], &length, sizeof(length))) abort();
  if (write_all(requests[1], data, size)) abort();
  unsigned char reply;
  if (read_all(replies[0], &reply, 1)) abort();
  return 0;
}
