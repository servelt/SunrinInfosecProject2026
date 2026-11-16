/*
 * Records which thread executed which function.
 *
 * Link this object into a build of the original program compiled with
 * -finstrument-functions.  When the environment variable HC_THREAD_TRACE names
 * a file, every (thread, function) pair seen during the run is written to it at
 * normal process exit as "<thread index> <link-time address in hex>".
 */
#define _GNU_SOURCE
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

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

HC_NOINSTR __attribute__((destructor)) static void hc_dump(void)
{
    const char *path = getenv("HC_THREAD_TRACE");
    FILE *out;
    uint32_t i;
    if (path == NULL || *path == '\0')
        return;
    out = fopen(path, "w");
    if (out == NULL)
        return;
    for (i = 0; i < HC_SLOTS; i++) {
        uint64_t key = hc_table[i];
        if (key != 0)
            fprintf(out, "%u %llx\n", (unsigned)(key >> 48), (unsigned long long)(key & 0xffffffffffffULL));
    }
    fclose(out);
}
