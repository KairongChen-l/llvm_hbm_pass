#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>

// 日志结构体：保存一个访存点的采样数据和顺序性判定
typedef struct {
    const char *func;       // 函数名
    int line;               // 源代码行号
    void **addresses;       // 动态数组，存储采样的地址序列
    size_t capacity;        // addresses 数组容量
    size_t size;            // 当前已记录的地址数量
    bool is_monotonic;      // 地址是否保持单调递增
    bool is_const_stride;   // 地址是否固定增量
    uintptr_t last_addr;    // 上一次记录的地址值（用于判定单调/增量）
    uintptr_t stride;       // 固定增量值（如果检测到）
    unsigned count;         // 采样计数器（用于定期采样）
} MemSiteLog;

// 全局日志列表及其锁
static MemSiteLog **g_logs = NULL;   // 动态数组，存放所有记录点的指针
static size_t g_log_count = 0;       // 已使用的元素个数
static size_t g_log_capacity = 0;    // 分配的容量
static pthread_mutex_t g_logs_lock = PTHREAD_MUTEX_INITIALIZER;

// 线程局部当前函数名和行号，由插桩代码负责设置
static _Thread_local const char *tls_func = NULL;
static _Thread_local int tls_line = 0;

// 线程局部指向当前线程日志数组的指针（若按线程分离存储，可用）
static _Thread_local MemSiteLog **tls_thread_logs = NULL;
static _Thread_local size_t tls_thread_log_count = 0;

// 定期采样的周期（每多少次访问记录一次）
#define SAMPLE_INTERVAL 100

// 工具函数：获取或创建指定源位置(func,line)的日志结构
static MemSiteLog* get_site_log(const char *func, int line) {
    // 查找是否已有该function+line的日志
    // 简单线性搜索（假设插桩点数量不会太大，可以优化为哈希）
    for (size_t i = 0; i < g_log_count; ++i) {
        if (g_logs[i]->line == line && strcmp(g_logs[i]->func, func) == 0) {
            return g_logs[i];
        }
    }
    // 未找到，则创建新日志节点
    MemSiteLog *log = (MemSiteLog*)malloc(sizeof(MemSiteLog));
    log->func = func;
    log->line = line;
    log->capacity = 1024; // 初始容量
    log->size = 0;
    log->addresses = (void**)malloc(log->capacity * sizeof(void*));
    log->is_monotonic = true;
    log->is_const_stride = true;
    log->last_addr = 0;
    log->stride = 0;
    log->count = 0;
    // 加入全局列表
    if (g_log_count >= g_log_capacity) {
        // 扩大全局列表容量
        size_t new_cap = g_log_capacity == 0 ? 16 : g_log_capacity * 2;
        MemSiteLog **new_arr = (MemSiteLog**)realloc(g_logs, new_cap * sizeof(MemSiteLog*));
        if (!new_arr) {
            fprintf(stderr, "Memory allocation failed for log list\n");
            exit(1);
        }
        g_logs = new_arr;
        g_log_capacity = new_cap;
    }
    g_logs[g_log_count++] = log;
    return log;
}

// 记录一次内存访问（由插桩调用）
// addr: 访问的地址; is_write: 是否写操作（true为写，false为读）
void record_mem_access(void *addr, bool is_write) {
    if (!tls_func) {
        // 若TLS中没有函数名信息，无法记录上下文，直接返回
        return;
    }
    // （可选）对全局或线程局部日志进行初始化，这里简单使用全局日志
    pthread_mutex_lock(&g_logs_lock);
    MemSiteLog *log = get_site_log(tls_func, tls_line);
    // 检查采样：只有当计数到达周期时才记录
    log->count++;
    if (log->count % SAMPLE_INTERVAL != 0) {
        // 未到记录周期，跳过记录此访问
        pthread_mutex_unlock(&g_logs_lock);
        return;
    }
    // 动态扩展地址数组如有必要
    if (log->size >= log->capacity) {
        size_t new_cap = log->capacity * 2;
        void **new_buf = (void**)realloc(log->addresses, new_cap * sizeof(void*));
        if (!new_buf) {
            fprintf(stderr, "Memory allocation failed for addresses\n");
            // 这里解锁并退出
            pthread_mutex_unlock(&g_logs_lock);
            exit(1);
        }
        log->addresses = new_buf;
        log->capacity = new_cap;
    }
    // 记录地址
    log->addresses[log->size++] = addr;
    // 更新顺序性判定
    uintptr_t addr_val = (uintptr_t)addr;
    if (log->size == 1) {
        // 第一条记录
        log->last_addr = addr_val;
        log->stride = 0;
    } else {
        if (addr_val <= log->last_addr) {
            log->is_monotonic = false;
        }
        uintptr_t delta = addr_val - log->last_addr;
        if (log->stride == 0) {
            // 第二条记录，设定初始步长
            log->stride = delta;
        } else if (delta != log->stride) {
            log->is_const_stride = false;
        }
        log->last_addr = addr_val;
    }
    pthread_mutex_unlock(&g_logs_lock);
    // （可根据is_write做不同处理，例如记录访问类型，目前未区分读取/写入输出）
}

// 程序退出时调用的函数：输出JSON并释放资源
static void output_profile_data(void) {
    const char *outfile = getenv("HBM_PROFILE_FILE");
    if (!outfile) {
        outfile = "hbm_profile.json";
    }
    FILE *fp = fopen(outfile, "w");
    if (!fp) {
        fprintf(stderr, "Failed to open output file %s\n", outfile);
        return;
    }
    pthread_mutex_lock(&g_logs_lock);
    fprintf(fp, "[\n");
    for (size_t i = 0; i < g_log_count; ++i) {
        MemSiteLog *log = g_logs[i];
        fprintf(fp, "  {\n");
        fprintf(fp, "    \"function\": \"%s\",\n", log->func);
        fprintf(fp, "    \"line\": %d,\n", log->line);
        // 输出地址数组
        fprintf(fp, "    \"addresses\": [");
        for (size_t j = 0; j < log->size; ++j) {
            // 将地址以十六进制字符串输出
            uintptr_t addr_val = (uintptr_t)log->addresses[j];
            fprintf(fp, "\"0x%lx\"", (unsigned long)addr_val);
            if (j < log->size - 1) fprintf(fp, ", ");
        }
        fprintf(fp, "],\n");
        // 输出顺序模式标志和步长
        fprintf(fp, "    \"monotonic\": %s,\n", log->is_monotonic ? "true" : "false");
        if (log->is_const_stride && log->stride != 0) {
            fprintf(fp, "    \"stride\": %lu\n", (unsigned long)log->stride);
        } else {
            fprintf(fp, "    \"stride\": null\n");
        }
        // 结束当前对象
        if (i < g_log_count - 1)
            fprintf(fp, "  },\n");
        else
            fprintf(fp, "  }\n");
        // 释放该日志的地址缓冲
        free(log->addresses);
        free(log);
    }
    fprintf(fp, "]\n");
    pthread_mutex_unlock(&g_logs_lock);
    fclose(fp);
}

// 将output_profile_data注册为atexit处理程序
__attribute__((constructor))
static void setup_atexit(void) {
    // 确保在程序正常结束时输出数据
    if (atexit(output_profile_data) != 0) {
        fprintf(stderr, "Failed to register atexit handler\n");
    }
}
