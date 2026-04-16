/*
 * simple_perf: minimal hardware performance counter reader for macOS.
 *
 * Measures cycles and instructions on the CURRENT thread around a workload,
 * then prints totals and IPC. Uses Apple's private kperf/kperfdata
 * frameworks via dlopen.
 *
 * Build:  clang -O2 -o simple_perf simple_perf.c
 * Run:    sudo ./simple_perf          (root required to touch PMCs)
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef size_t   usize;

// kperf/kpc classes: fixed = cycles/instructions, configurable = the rest.
#define KPC_CLASS_FIXED_MASK        (1u << 0)
#define KPC_CLASS_CONFIGURABLE_MASK (1u << 1)
#define KPC_MAX_COUNTERS            32

// --- Function pointers we resolve at runtime via dlsym -----------------------

// kpc = the low-level counter driver.
static int  (*kpc_force_all_ctrs_get)(int *val_out);
static int  (*kpc_force_all_ctrs_set)(int val);
static u32  (*kpc_get_counter_count)(u32 classes);
static int  (*kpc_set_config)(u32 classes, u64 *config);
static int  (*kpc_set_counting)(u32 classes);
static int  (*kpc_set_thread_counting)(u32 classes);
static int  (*kpc_get_thread_counters)(u32 tid, u32 buf_count, u64 *buf);

// kpep = the event database (maps event names like "FIXED_CYCLES" to PMC config bits).
typedef struct kpep_db kpep_db;
typedef struct kpep_config kpep_config;
typedef struct kpep_event kpep_event;

static int  (*kpep_db_create)(const char *name, kpep_db **out);
static int  (*kpep_db_event)(kpep_db *db, const char *name, kpep_event **out);
static int  (*kpep_config_create)(kpep_db *db, kpep_config **out);
static int  (*kpep_config_force_counters)(kpep_config *cfg);
static int  (*kpep_config_add_event)(kpep_config *cfg, kpep_event **ev, u32 flag, u32 *err);
static int  (*kpep_config_kpc_classes)(kpep_config *cfg, u32 *out);
static int  (*kpep_config_kpc_count)(kpep_config *cfg, usize *out);
static int  (*kpep_config_kpc_map)(kpep_config *cfg, usize *buf, usize size);
static int  (*kpep_config_kpc)(kpep_config *cfg, u64 *buf, usize size);

#define KPERF_PATH     "/System/Library/PrivateFrameworks/kperf.framework/kperf"
#define KPERFDATA_PATH "/System/Library/PrivateFrameworks/kperfdata.framework/kperfdata"

#define LOAD(lib, sym) do {                                         \
    sym = dlsym(lib, #sym);                                         \
    if (!sym) { fprintf(stderr, "dlsym %s failed\n", #sym); return 1; } \
} while (0)

static int load_frameworks(void) {
    void *kperf     = dlopen(KPERF_PATH,     RTLD_LAZY);
    void *kperfdata = dlopen(KPERFDATA_PATH, RTLD_LAZY);
    if (!kperf || !kperfdata) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }
    LOAD(kperf, kpc_force_all_ctrs_get);
    LOAD(kperf, kpc_force_all_ctrs_set);
    LOAD(kperf, kpc_get_counter_count);
    LOAD(kperf, kpc_set_config);
    LOAD(kperf, kpc_set_counting);
    LOAD(kperf, kpc_set_thread_counting);
    LOAD(kperf, kpc_get_thread_counters);

    LOAD(kperfdata, kpep_db_create);
    LOAD(kperfdata, kpep_db_event);
    LOAD(kperfdata, kpep_config_create);
    LOAD(kperfdata, kpep_config_force_counters);
    LOAD(kperfdata, kpep_config_add_event);
    LOAD(kperfdata, kpep_config_kpc_classes);
    LOAD(kperfdata, kpep_config_kpc_count);
    LOAD(kperfdata, kpep_config_kpc_map);
    LOAD(kperfdata, kpep_config_kpc);
    return 0;
}

// A trivial workload so there's something to measure.
static u64 workload(void) {
    u64 sum = 0;
    for (u64 i = 0; i < 50ull * 1000 * 1000; i++) sum += i * 3 + 1;
    return sum;
}

int main(void) {
    if (load_frameworks()) return 1;

    // Root check: kpc_force_all_ctrs_get only succeeds as root.
    int forced = 0;
    if (kpc_force_all_ctrs_get(&forced)) {
        fprintf(stderr, "Need root: run with sudo\n");
        return 1;
    }

    // 1. Build the event database and a config we'll populate with events.
    kpep_db *db = NULL;
    if (kpep_db_create(NULL, &db)) { fprintf(stderr, "kpep_db_create\n"); return 1; }

    kpep_config *cfg = NULL;
    if (kpep_config_create(db, &cfg))         { fprintf(stderr, "config_create\n"); return 1; }
    if (kpep_config_force_counters(cfg))      { fprintf(stderr, "force_counters\n"); return 1; }

    // 2. Add two events. "FIXED_*" are Apple Silicon names; they map to the
    //    fixed-function cycles/instructions counters every modern CPU has.
    const char *event_names[2] = { "FIXED_CYCLES", "FIXED_INSTRUCTIONS" };
    for (int i = 0; i < 2; i++) {
        kpep_event *ev = NULL;
        if (kpep_db_event(db, event_names[i], &ev) || !ev) {
            fprintf(stderr, "unknown event %s (Intel mac?)\n", event_names[i]);
            return 1;
        }
        u32 err = 0;
        if (kpep_config_add_event(cfg, &ev, 0, &err)) {
            fprintf(stderr, "add_event %s err=0x%x\n", event_names[i], err);
            return 1;
        }
    }

    // 3. Ask kpep to translate our event list into (a) the counter classes we
    //    need, (b) the raw per-register config values, and (c) a map from our
    //    event index -> which hardware counter slot it lands in.
    u32 classes = 0;
    usize reg_count = 0;
    u64  regs[KPC_MAX_COUNTERS] = {0};
    usize counter_map[KPC_MAX_COUNTERS] = {0};

    if (kpep_config_kpc_classes(cfg, &classes) ||
        kpep_config_kpc_count(cfg, &reg_count) ||
        kpep_config_kpc_map(cfg, counter_map, sizeof(counter_map)) ||
        kpep_config_kpc(cfg, regs, sizeof(regs))) {
        fprintf(stderr, "kpc config extract failed\n");
        return 1;
    }

    // 4. Push the config into the kernel and enable counting.
    if (kpc_force_all_ctrs_set(1))         { fprintf(stderr, "force_all_ctrs_set\n"); return 1; }
    if (classes & KPC_CLASS_CONFIGURABLE_MASK) {
        if (kpc_set_config(classes, regs)) { fprintf(stderr, "kpc_set_config\n"); return 1; }
    }
    if (kpc_set_counting(classes))         { fprintf(stderr, "set_counting\n"); return 1; }
    if (kpc_set_thread_counting(classes))  { fprintf(stderr, "set_thread_counting\n"); return 1; }

    u32 counter_count = kpc_get_counter_count(classes);

    // 5. Read counters, run workload, read again. Delta = work we did.
    u64 before[KPC_MAX_COUNTERS] = {0};
    u64 after[KPC_MAX_COUNTERS]  = {0};

    if (kpc_get_thread_counters(0, counter_count, before)) {
        fprintf(stderr, "get_thread_counters (before)\n"); return 1;
    }

    u64 sink = workload();

    if (kpc_get_thread_counters(0, counter_count, after)) {
        fprintf(stderr, "get_thread_counters (after)\n"); return 1;
    }

    // 6. counter_map[i] tells us which slot holds event i's value.
    u64 cycles       = after[counter_map[0]] - before[counter_map[0]];
    u64 instructions = after[counter_map[1]] - before[counter_map[1]];

    printf("workload sink: %llu\n", (unsigned long long)sink);
    printf("cycles:        %llu\n", (unsigned long long)cycles);
    printf("instructions:  %llu\n", (unsigned long long)instructions);
    if (cycles) printf("IPC:           %.2f\n", (double)instructions / cycles);

    // 7. Turn counting off so we leave the system clean.
    kpc_set_counting(0);
    kpc_set_thread_counting(0);
    kpc_force_all_ctrs_set(0);
    return 0;
}
