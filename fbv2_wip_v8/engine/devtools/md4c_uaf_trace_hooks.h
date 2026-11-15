#ifndef FBV2_MD4C_UAF_TRACE_HOOKS_H
#define FBV2_MD4C_UAF_TRACE_HOOKS_H

/* Development-only causal measurement hooks. Never compile into release md4c. */
#if defined(FBV2_UAF_CAUSAL_TRACE)

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

typedef struct FBV2_UAF_TRACE_STATE_tag {
    const void* input;
    size_t input_size;
    const void* current_base;
    size_t current_size;
    unsigned long generation;
    const char* allocation_file;
    int allocation_line;
    const void* stale_pointer;
    const void* old_base;
    size_t old_size;
    const void* new_base;
    size_t new_size;
    const char* reallocation_file;
    int reallocation_line;
    int moved_reallocation;
} FBV2_UAF_TRACE_STATE;

static FBV2_UAF_TRACE_STATE fbv2_uaf_trace;

static void
fbv2_uaf_trace_input(const void* input, size_t size)
{
    fbv2_uaf_trace.input = input;
    fbv2_uaf_trace.input_size = size;
}

static void
fbv2_uaf_trace_stale_candidate(const void* pointer)
{
    fbv2_uaf_trace.stale_pointer = pointer;
}

static void
fbv2_uaf_trace_successful_reallocation(const void* old_base, size_t old_size,
                                       const void* new_base, size_t new_size,
                                       const char* file, int line)
{
    const char* previous_file = fbv2_uaf_trace.allocation_file;
    int previous_line = fbv2_uaf_trace.allocation_line;
    unsigned long previous_generation = fbv2_uaf_trace.generation;
    int old_object_was_tracked =
        (fbv2_uaf_trace.current_base == old_base &&
         fbv2_uaf_trace.current_size == old_size && old_base != NULL);

    fbv2_uaf_trace.moved_reallocation =
        (old_object_was_tracked && new_base != NULL && new_base != old_base &&
         new_size > 0 &&
         (uintptr_t) fbv2_uaf_trace.stale_pointer >= (uintptr_t) old_base &&
         (uintptr_t) fbv2_uaf_trace.stale_pointer - (uintptr_t) old_base <
             old_size);
    if(fbv2_uaf_trace.moved_reallocation) {
        fbv2_uaf_trace.old_base = old_base;
        fbv2_uaf_trace.old_size = old_size;
        fbv2_uaf_trace.new_base = new_base;
        fbv2_uaf_trace.new_size = new_size;
        fbv2_uaf_trace.reallocation_file = file;
        fbv2_uaf_trace.reallocation_line = line;
        fbv2_uaf_trace.generation = previous_generation;
        fbv2_uaf_trace.allocation_file = previous_file;
        fbv2_uaf_trace.allocation_line = previous_line;
    }
    fbv2_uaf_trace.current_base = new_base;
    fbv2_uaf_trace.current_size = new_size;
    if(!fbv2_uaf_trace.moved_reallocation) {
        fbv2_uaf_trace.generation = previous_generation + 1;
        fbv2_uaf_trace.allocation_file = file;
        fbv2_uaf_trace.allocation_line = line;
    }
}

static void
fbv2_uaf_trace_access(const void* pointer_base, const void* access_address,
                      size_t width, const char* operation,
                      const char* function_name, const char* file, int line)
{
    const char* trace_path = getenv("FBV2_TRACE_PATH");
    const char* evaluation_id = getenv("FBV2_EVALUATION_ID");
    const char* input_sha256 = getenv("FBV2_INPUT_SHA256");
    char json[8192];
    int length;
    int fd;
    ptrdiff_t offset;
    uintptr_t old_address;
    uintptr_t access_value;
    uintptr_t pointer_value;

    old_address = (uintptr_t) fbv2_uaf_trace.old_base;
    access_value = (uintptr_t) access_address;
    pointer_value = (uintptr_t) pointer_base;
    if(!fbv2_uaf_trace.moved_reallocation || trace_path == NULL ||
       evaluation_id == NULL || input_sha256 == NULL ||
       strlen(input_sha256) != 64 || pointer_base == NULL ||
       access_address == NULL || access_value < old_address ||
       width > fbv2_uaf_trace.old_size ||
       access_value - old_address > fbv2_uaf_trace.old_size - width ||
       access_value < pointer_value ||
       access_value - pointer_value > (uintptr_t) PTRDIFF_MAX)
        return;
    offset = (ptrdiff_t) (access_value - pointer_value);
    length = snprintf(json, sizeof(json),
        "{\"kind\":\"FBV2_UAF_RAW_TRACE_V1\","
        "\"evaluation_id\":\"%s\",\"input_sha256\":\"%s\","
        "\"events\":["
        "{\"kind\":\"input_read\",\"sequence\":0,"
        "\"input_sha256\":\"%s\",\"input_size\":%zu},"
        "{\"kind\":\"allocation\",\"sequence\":1,"
        "\"generation\":%lu,\"base\":\"%p\",\"size\":%zu,"
        "\"function_name\":\"md_push_block_bytes\","
        "\"source_file\":\"%s\",\"line\":%d},"
        "{\"kind\":\"reallocation\",\"sequence\":2,"
        "\"generation\":%lu,\"old_base\":\"%p\",\"old_size\":%zu,"
        "\"new_base\":\"%p\",\"new_size\":%zu,"
        "\"pointer_before\":\"%p\",\"pointer_after\":\"%p\","
        "\"function_name\":\"md_push_block_bytes\","
        "\"source_file\":\"%s\",\"line\":%d},"
        "{\"kind\":\"access\",\"sequence\":3,\"generation\":%lu,"
        "\"pointer_base\":\"%p\",\"pointer_offset\":%td,"
        "\"address\":\"%p\",\"width\":%zu,\"operation\":\"%s\","
        "\"function_name\":\"%s\",\"source_file\":\"%s\","
        "\"line\":%d}]}\n",
        evaluation_id, input_sha256, input_sha256,
        fbv2_uaf_trace.input_size,
        fbv2_uaf_trace.generation, fbv2_uaf_trace.old_base,
        fbv2_uaf_trace.old_size, fbv2_uaf_trace.allocation_file,
        fbv2_uaf_trace.allocation_line,
        fbv2_uaf_trace.generation, fbv2_uaf_trace.old_base,
        fbv2_uaf_trace.old_size, fbv2_uaf_trace.new_base,
        fbv2_uaf_trace.new_size, fbv2_uaf_trace.stale_pointer,
        fbv2_uaf_trace.stale_pointer, fbv2_uaf_trace.reallocation_file,
        fbv2_uaf_trace.reallocation_line,
        fbv2_uaf_trace.generation, pointer_base, offset, access_address,
        width, operation, function_name, file, line);
    if(length <= 0 || (size_t) length >= sizeof(json))
        return;
    fd = open(trace_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if(fd < 0)
        return;
    if(write(fd, json, (size_t) length) == length)
        fsync(fd);
    close(fd);
}

#define FBV2_TRACE_INPUT(input, size) \
    fbv2_uaf_trace_input((input), (size))
#define FBV2_TRACE_STALE(pointer) \
    fbv2_uaf_trace_stale_candidate((pointer))
#define FBV2_TRACE_REALLOC(old_base, old_size, new_base, new_size) \
    fbv2_uaf_trace_successful_reallocation( \
        (old_base), (old_size), (new_base), (new_size), __FILE__, __LINE__)
#define FBV2_TRACE_REALLOC_AT(old_base, old_size, new_base, new_size, line) \
    fbv2_uaf_trace_successful_reallocation( \
        (old_base), (old_size), (new_base), (new_size), __FILE__, (line))
#define FBV2_TRACE_ACCESS(base, address, width, operation, function_name) \
    fbv2_uaf_trace_access((base), (address), (width), (operation), \
                          (function_name), __FILE__, __LINE__)

#else
#define FBV2_TRACE_INPUT(input, size) ((void) 0)
#define FBV2_TRACE_STALE(pointer) ((void) 0)
#define FBV2_TRACE_REALLOC(old_base, old_size, new_base, new_size) ((void) 0)
#define FBV2_TRACE_REALLOC_AT(old_base, old_size, new_base, new_size, line) \
    ((void) 0)
#define FBV2_TRACE_ACCESS(base, address, width, operation, function_name) \
    ((void) 0)
#endif

#endif
