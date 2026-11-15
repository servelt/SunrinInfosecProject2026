/* Coverage build only: flush gcov counters when the harness stops the program with a signal.
   ProFuzzBench patches its subjects the same way; the analysed source and the harness build
   are left unmodified. */
#define _GNU_SOURCE
#include <signal.h>
#include <unistd.h>

void __gcov_dump(void);

static void fba_flush(int sig)
{
    (void)sig;
    __gcov_dump();
    _exit(0);
}

__attribute__((constructor)) static void fba_install(void)
{
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = fba_flush;
    sigaction(SIGTERM, &sa, 0);
    sigaction(SIGINT, &sa, 0);
}
