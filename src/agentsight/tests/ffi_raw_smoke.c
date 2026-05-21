/**
 * ffi_raw_smoke.c — Step 4 FFI raw event 回调接口 smoke test
 *
 * 编译:
 *   gcc -O2 -o ffi_raw_smoke tests/ffi_raw_smoke.c -ldl -lpthread
 *
 * 运行 (需 root 权限以加载 BPF):
 *   sudo LD_LIBRARY_PATH=target/release ./ffi_raw_smoke [target_pid]
 *
 * 若不指定 target_pid，默认 attach 自身 pid。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <signal.h>
#include <sys/epoll.h>
#include <stdint.h>
#include <time.h>

/* ---- Struct definitions (mirrors cbindgen output) ---- */

typedef struct AgentsightRawEventData {
    uint64_t timestamp_ms;
    const char *source;
    uint32_t pid;
    uint32_t ppid;
    uint32_t tid;
    uint32_t uid;
    char comm[16];
    uint64_t cgroup_id;
    const char *op;
    int32_t ret;
    const char *data_json;
    uint32_t data_json_len;
    uint32_t count;
} AgentsightRawEventData;

typedef struct AgentsightConfigHandle AgentsightConfigHandle;
typedef struct AgentsightHandle AgentsightHandle;

/* ---- Callback types ---- */
typedef void (*agentsight_raw_event_callback_fn)(const AgentsightRawEventData *data, void *user_data);
typedef void (*agentsight_https_callback_fn)(const void *data, void *user_data);
typedef void (*agentsight_llm_callback_fn)(const void *data, void *user_data);

/* ---- Function pointer types ---- */
typedef AgentsightConfigHandle *(*fn_config_new)(void);
typedef void (*fn_config_set_verbose)(AgentsightConfigHandle *, int);
typedef void (*fn_config_set_raw_events)(AgentsightConfigHandle *, int);
typedef void (*fn_config_set_raw_events_ffi)(AgentsightConfigHandle *, int);
typedef int  (*fn_config_load_config)(AgentsightConfigHandle *, const char *);
typedef void (*fn_config_free)(AgentsightConfigHandle *);

typedef AgentsightHandle *(*fn_new)(AgentsightConfigHandle *);
typedef int  (*fn_start)(AgentsightHandle *);
typedef int  (*fn_stop)(AgentsightHandle *);
typedef void (*fn_free)(AgentsightHandle *);

typedef int  (*fn_get_raw_eventfd)(AgentsightHandle *);
typedef int  (*fn_read_raw)(AgentsightHandle *, agentsight_raw_event_callback_fn, void *, int);
typedef const char *(*fn_last_error)(void);

/* ---- Globals ---- */
static volatile sig_atomic_t g_running = 1;
static uint64_t g_event_count = 0;

static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/* ---- Raw event callback ---- */
static void on_raw_event(const AgentsightRawEventData *data, void *user_data) {
    (void)user_data;
    g_event_count++;

    /* 前 20 条详细打印，之后每 100 条打印一次摘要 */
    if (g_event_count <= 20 || g_event_count % 100 == 0) {
        char comm_buf[17] = {0};
        memcpy(comm_buf, data->comm, 16);

        printf("[raw #%lu] ts=%lu src=%-10s pid=%-6u ppid=%-6u comm=%-15s "
               "op=%-12s ret=%d cgroup=%lu json_len=%u\n",
               (unsigned long)g_event_count,
               (unsigned long)data->timestamp_ms,
               data->source ? data->source : "(null)",
               data->pid, data->ppid, comm_buf,
               data->op ? data->op : "(null)",
               data->ret,
               (unsigned long)data->cgroup_id,
               data->data_json_len);

        /* 打印 data_json 前 200 字节 */
        if (data->data_json && data->data_json_len > 0) {
            int print_len = data->data_json_len < 200 ? data->data_json_len : 200;
            printf("       json: %.*s%s\n", print_len, data->data_json,
                   data->data_json_len > 200 ? "..." : "");
        }
    }
}

/* ---- Helper: load symbol or die ---- */
static void *load_sym(void *lib, const char *name) {
    void *sym = dlsym(lib, name);
    if (!sym) {
        fprintf(stderr, "ERROR: dlsym(%s) failed: %s\n", name, dlerror());
        exit(1);
    }
    return sym;
}

int main(int argc, char *argv[]) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* ---- Load libagentsight.so ---- */
    const char *lib_path = "libagentsight.so";
    void *lib = dlopen(lib_path, RTLD_NOW);
    if (!lib) {
        fprintf(stderr, "ERROR: dlopen(%s) failed: %s\n", lib_path, dlerror());
        fprintf(stderr, "HINT: 确认 LD_LIBRARY_PATH 包含 target/release 目录\n");
        return 1;
    }
    printf("✓ loaded %s\n", lib_path);

    /* ---- Resolve symbols ---- */
    fn_config_new           p_config_new           = (fn_config_new)load_sym(lib, "agentsight_config_new");
    fn_config_set_verbose   p_config_set_verbose   = (fn_config_set_verbose)load_sym(lib, "agentsight_config_set_verbose");
    fn_config_set_raw_events     p_config_set_raw_events     = (fn_config_set_raw_events)load_sym(lib, "agentsight_config_set_raw_events");
    fn_config_set_raw_events_ffi p_config_set_raw_events_ffi = (fn_config_set_raw_events_ffi)load_sym(lib, "agentsight_config_set_raw_events_ffi");
    fn_config_load_config   p_config_load_config   = (fn_config_load_config)load_sym(lib, "agentsight_config_load_config");
    fn_config_free          p_config_free          = (fn_config_free)load_sym(lib, "agentsight_config_free");
    fn_new                  p_new                  = (fn_new)load_sym(lib, "agentsight_new");
    fn_start                p_start                = (fn_start)load_sym(lib, "agentsight_start");
    fn_stop                 p_stop                 = (fn_stop)load_sym(lib, "agentsight_stop");
    fn_free                 p_free                 = (fn_free)load_sym(lib, "agentsight_free");
    fn_get_raw_eventfd      p_get_raw_eventfd      = (fn_get_raw_eventfd)load_sym(lib, "agentsight_get_raw_eventfd");
    fn_read_raw             p_read_raw             = (fn_read_raw)load_sym(lib, "agentsight_read_raw");
    fn_last_error           p_last_error           = (fn_last_error)load_sym(lib, "agentsight_last_error");

    printf("✓ all symbols resolved\n");

    /* ---- Configure ---- */
    AgentsightConfigHandle *cfg = p_config_new();
    if (!cfg) {
        fprintf(stderr, "ERROR: agentsight_config_new() returned NULL\n");
        return 1;
    }

    /* 启用 verbose 日志便于调试 */
    p_config_set_verbose(cfg, 1);

    /* 启用 raw events FFI 通道 */
    p_config_set_raw_events_ffi(cfg, 1);

    /* 同时启用 SQLite 落库（验证双 sink 兼容） */
    p_config_set_raw_events(cfg, 1);

    /* 通过 JSON 配置 pid 和探针 */
    uint32_t target_pid = (argc > 1) ? (uint32_t)atoi(argv[1]) : (uint32_t)getpid();
    char json_cfg[512];
    snprintf(json_cfg, sizeof(json_cfg),
        "{"
        "  \"target_pids\": [%u],"
        "  \"raw_events_enabled\": true,"
        "  \"raw_events_ffi\": true,"
        "  \"probes\": {"
        "    \"procmon\": false,"
        "    \"proctrace\": true,"
        "    \"procfs\": true,"
        "    \"procnet\": true,"
        "    \"procsig\": true,"
        "    \"filewatch\": true"
        "  }"
        "}",
        target_pid);

    if (p_config_load_config(cfg, json_cfg) != 0) {
        const char *err = p_last_error();
        fprintf(stderr, "ERROR: config_load_config failed: %s\n", err ? err : "(unknown)");
        p_config_free(cfg);
        return 1;
    }
    printf("✓ config loaded (target_pid=%u)\n", target_pid);

    /* ---- Create handle ---- */
    AgentsightHandle *h = p_new(cfg);
    p_config_free(cfg);
    if (!h) {
        const char *err = p_last_error();
        fprintf(stderr, "ERROR: agentsight_new() failed: %s\n", err ? err : "(unknown)");
        return 1;
    }

    /* ---- Get raw eventfd ---- */
    int raw_efd = p_get_raw_eventfd(h);
    if (raw_efd < 0) {
        fprintf(stderr, "ERROR: agentsight_get_raw_eventfd() returned %d\n", raw_efd);
        p_free(h);
        return 1;
    }
    printf("✓ raw_eventfd = %d\n", raw_efd);

    /* ---- Start pipeline ---- */
    if (p_start(h) != 0) {
        const char *err = p_last_error();
        fprintf(stderr, "ERROR: agentsight_start() failed: %s\n", err ? err : "(unknown)");
        p_free(h);
        return 1;
    }
    printf("✓ pipeline started, waiting for events... (Ctrl+C to stop)\n\n");

    /* ---- epoll loop ---- */
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        perror("epoll_create1");
        p_stop(h);
        p_free(h);
        return 1;
    }

    struct epoll_event ev = { .events = EPOLLIN, .data.fd = raw_efd };
    epoll_ctl(epfd, EPOLL_CTL_ADD, raw_efd, &ev);

    struct epoll_event events[4];
    time_t start_time = time(NULL);

    while (g_running) {
        int nfds = epoll_wait(epfd, events, 4, 1000 /* 1s timeout */);
        if (nfds < 0) {
            if (g_running) perror("epoll_wait");
            break;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == raw_efd) {
                /* Non-blocking drain all pending raw events */
                int n = p_read_raw(h, on_raw_event, NULL, 0);
                if (n < 0) {
                    fprintf(stderr, "ERROR: agentsight_read_raw() returned %d\n", n);
                    g_running = 0;
                }
            }
        }

        /* 每 5 秒输出统计 */
        time_t now = time(NULL);
        if ((now - start_time) % 5 == 0 && now != start_time) {
            printf("--- [%lds elapsed] total raw events: %lu ---\n",
                   (long)(now - start_time), (unsigned long)g_event_count);
        }
    }

    /* ---- Cleanup ---- */
    printf("\n--- SUMMARY ---\n");
    printf("Total raw events received: %lu\n", (unsigned long)g_event_count);
    printf("Elapsed: %lds\n", (long)(time(NULL) - start_time));

    p_stop(h);
    p_free(h);
    close(epfd);
    dlclose(lib);

    printf("✓ cleanup done\n");
    return (g_event_count > 0) ? 0 : 1;
}
