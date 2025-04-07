#include <stdint.h>
#include <time.h>
#include <stdio.h>

static uint64_t total_bytes = 0;
static double start_time = 0.0;
static double end_time = 0.0;

static double get_time_sec() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

void record_start_time() {
    total_bytes = 0;
    start_time = get_time_sec();
}

void record_access_stats(uint64_t size) {
    total_bytes += size;
}

void record_end_time() {
    end_time = get_time_sec();
    double duration = end_time - start_time;
    if (duration < 1e-6) duration = 1e-6;
    double bw = (double)total_bytes / 1024.0 / 1024.0 / 1024.0 / duration;
    printf("[BW] %.2f GB/s (%.2f MB in %.4f s)\n", bw, total_bytes / 1024.0 / 1024.0, duration);
    // 可写入全局结构，后续关联 MallocRecord 更新
}
#include <stdint.h>
#include <time.h>
#include <stdio.h>

static uint64_t total_bytes = 0;
static double start_time = 0.0;
static double end_time = 0.0;

static double get_time_sec() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

void record_start_time() {
    total_bytes = 0;
    start_time = get_time_sec();
}

void record_access_stats(uint64_t size) {
    total_bytes += size;
}

void record_end_time() {
    end_time = get_time_sec();
    double duration = end_time - start_time;
    if (duration < 1e-6) duration = 1e-6;
    double bw = (double)total_bytes / 1024.0 / 1024.0 / 1024.0 / duration;
    printf("[BW] %.2f GB/s (%.2f MB in %.4f s)\n", bw, total_bytes / 1024.0 / 1024.0, duration);
    // 可写入全局结构，后续关联 MallocRecord 更新
}
