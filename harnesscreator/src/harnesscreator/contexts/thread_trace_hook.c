/*
 * Records which thread executed which function.
 *
 * Link this object into a build of the original program compiled with
 * -finstrument-functions.  When the environment variable HC_THREAD_TRACE names
 * a file, every (thread, function) pair seen during the run is written to it at
 * process exit as "<thread index> <link-time address in hex>" -- normal exit, or
 * SIGTERM/SIGINT when the program leaves those signals at their default (it then
 * dies without running destructors, and nothing was written: measured on an FTP
 * daemon stopped with SIGTERM after every seed).
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <link.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HC_SLOTS (1u << 20)
#define HC_NOINSTR __attribute__((no_instrument_function))

static uint64_t hc_table[HC_SLOTS];
static int hc_next_thread = 1;
static __thread int hc_thread;
static uintptr_t hc_bias;
static int hc_bias_known;

HC_NOINSTR static int hc_phdr(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size; (void)data;
    hc_bias = (uintptr_t)info->dlpi_addr;   /* first entry is the main program */
    return 1;
}

HC_NOINSTR void __cyg_profile_func_enter(void *fn, void *site)
{
    uint64_t key, expected;
    uint32_t slot, probe;
    (void)site;
    if (!hc_bias_known) {
        dl_iterate_phdr(hc_phdr, NULL);
        hc_bias_known = 1;
    }
    if (hc_thread == 0)
        hc_thread = __atomic_fetch_add(&hc_next_thread, 1, __ATOMIC_RELAXED);
    key = ((uint64_t)hc_thread << 48) | (((uintptr_t)fn - hc_bias) & 0xffffffffffffULL);
    slot = (uint32_t)((key * 0x9e3779b97f4a7c15ULL) >> 44) & (HC_SLOTS - 1);
    for (probe = 0; probe < 64; probe++) {
        uint64_t current = __atomic_load_n(&hc_table[slot], __ATOMIC_RELAXED);
        if (current == key)
            return;
        if (current == 0) {
            expected = 0;
            if (__atomic_compare_exchange_n(&hc_table[slot], &expected, key, 0,
                                            __ATOMIC_RELAXED, __ATOMIC_RELAXED) || expected == key)
                return;
        }
        slot = (slot + 1) & (HC_SLOTS - 1);
    }
}

HC_NOINSTR void __cyg_profile_func_exit(void *fn, void *site)
{
    (void)fn; (void)site;
}

/* Async-signal-safe: open/write only, the line formatted by hand. */
HC_NOINSTR static void hc_write_table(void)
{
    const char *path = getenv("HC_THREAD_TRACE");
    char line[48];
    int fd;
    uint32_t i;
    if (path == NULL || *path == '\0')
        return;
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return;
    for (i = 0; i < HC_SLOTS; i++) {
        uint64_t key = hc_table[i], value;
        unsigned thread;
        char digits[24];
        int n = 0, d = 0;
        if (key == 0)
            continue;
        thread = (unsigned)(key >> 48);
        value = key & 0xffffffffffffULL;
        do { digits[d++] = (char)('0' + thread % 10); thread /= 10; } while (thread && d < 10);
        while (d) line[n++] = digits[--d];
        line[n++] = ' ';
        do { digits[d++] = "0123456789abcdef"[value & 0xf]; value >>= 4; } while (value && d < 16);
        while (d) line[n++] = digits[--d];
        line[n++] = '\n';
        if (write(fd, line, (size_t)n) < 0)
            break;
    }
    close(fd);
}

HC_NOINSTR __attribute__((destructor)) static void hc_dump(void)
{
    hc_write_table();
}

HC_NOINSTR static void hc_on_signal(int sig)
{
    hc_write_table();
    signal(sig, SIG_DFL);           /* then die of the same signal, as the program would have */
    raise(sig);
}

HC_NOINSTR __attribute__((constructor)) static void hc_install(void)
{
    static const int signals[] = {SIGTERM, SIGINT};
    unsigned i;
    for (i = 0; i < sizeof(signals) / sizeof(signals[0]); i++) {
        struct sigaction current;
        if (sigaction(signals[i], NULL, &current) == 0 && current.sa_handler == SIG_DFL) {
            struct sigaction ours;
            memset(&ours, 0, sizeof(ours));
            ours.sa_handler = hc_on_signal;
            sigemptyset(&ours.sa_mask);
            sigaction(signals[i], &ours, NULL);
        }
    }
}
