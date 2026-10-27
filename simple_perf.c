/*
 * simple_perf: a small `perf`-like tool for Apple Silicon Macs, built on the
 * private kperf / kperfdata frameworks (dlopen'd at runtime, no headers).
 *
 *   simple_perf list   [pattern]               PMU events for this CPU
 *   simple_perf stat   [opts] [--] cmd [args]  count events for a command
 *   simple_perf record [opts] [--] cmd [args]  sample call stacks (on-CPU profile)
 *   simple_perf bench  [-e ev,...] [name...]   built-in microbenchmarks, exact thread counters
 *   simple_perf info                           PMU / CPU details
 *
 * Build:  clang -O2 -o simple_perf simple_perf.c
 *
 * Root: `list`, `info` and plain `stat` (cycles / instructions / P-core split /
 * energy come from proc_pid_rusage) work unprivileged. Anything that programs
 * the PMU or kperf (`stat -e/-a/-d`, `bench`, `record`) needs sudo.
 *
 * re/NOTES.md documents how the private APIs used here were reverse engineered.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <math.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <dlfcn.h>
#include <spawn.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/sysctl.h>
#include <sys/resource.h>
#include <libproc.h>
#include <mach/mach_time.h>
#include <mach/vm_prot.h>
#include <uuid/uuid.h>

extern char **environ;

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint8_t  u8;
typedef size_t   usize;

// kperf/kpc classes: fixed = cycles/instructions, configurable = the rest.
#define KPC_CLASS_FIXED_MASK        (1u << 0)
#define KPC_CLASS_CONFIGURABLE_MASK (1u << 1)
#define KPC_MAX_COUNTERS            32
#define KPC_MAX_CPUS                512

// Mode bits in an Apple PMU config word. kpep sets EL0 when add_event's flag
// bit 0 is set; with neither bit set the kernel counts in all modes.
#define CFG_EL0 0x20000ull
#define CFG_EL1 0x40000ull

// kpep error code for "event doesn't fit next to the others" (kpep_strerror(12)).
#define KPEP_ERR_CONFLICT 12

#define MAX_EVENTS 64

// --- Function pointers we resolve at runtime via dlsym -----------------------

// kpc = the low-level counter driver (thin wrappers over kpc.* sysctls).
static int  (*kpc_force_all_ctrs_get)(int *val_out);
static int  (*kpc_force_all_ctrs_set)(int val);
static u32  (*kpc_get_counter_count)(u32 classes);
static u32  (*kpc_get_config_count)(u32 classes);
static int  (*kpc_set_config)(u32 classes, u64 *config);
static int  (*kpc_set_counting)(u32 classes);
static int  (*kpc_set_thread_counting)(u32 classes);
static int  (*kpc_get_thread_counters)(u32 tid, u32 buf_count, u64 *buf);
// all_cpus=1 fills buf with ncpu * counter_count values, CPU-major.
static int  (*kpc_get_cpu_counters)(int all_cpus, u32 classes, int *curcpu, u64 *buf);
static int  (*kpc_cpu_string)(char *buf, usize len);

// kperf = the sampling engine (timers -> actions -> samplers -> kdebug buffer).
static int  (*kperf_reset)(void);
static int  (*kperf_sample_set)(u32 enabled);
static int  (*kperf_action_count_set)(u32 count);
static int  (*kperf_action_samplers_set)(u32 actionid, u32 samplers);
static int  (*kperf_action_filter_set_by_pid)(u32 actionid, int pid);
static int  (*kperf_timer_count_set)(u32 count);
static int  (*kperf_timer_period_set)(u32 timerid, u64 ticks);
static int  (*kperf_timer_action_set)(u32 timerid, u32 actionid);
static u64  (*kperf_ns_to_ticks)(u64 ns);

// kpep = the event database (maps event names like "FIXED_CYCLES" to PMC config bits).
typedef struct kpep_db kpep_db;
typedef struct kpep_config kpep_config;

// Leading fields of kpep's event struct; offsets confirmed by reading events
// back against /usr/share/kpep/as4.plist.
typedef struct kpep_event {
    const char *name;
    const char *description;
    const char *errata;
    const char *alias;          // e.g. "Cycles"
    const char *fallback;       // e.g. FIXED_INSTRUCTIONS -> INST_ALL
    u32         counters_mask;  // which counter slots may host this event
    u32         number;         // raw event number
    u8          is_fixed;
} kpep_event;

static int  (*kpep_db_create)(const char *name, kpep_db **out);
static int  (*kpep_db_name)(kpep_db *db, const char **out);
static int  (*kpep_db_events_count)(kpep_db *db, usize *out);
static int  (*kpep_db_events)(kpep_db *db, kpep_event **buf, usize buf_bytes);
static int  (*kpep_config_create)(kpep_db *db, kpep_config **out);
static int  (*kpep_config_force_counters)(kpep_config *cfg);
static int  (*kpep_config_add_event)(kpep_config *cfg, kpep_event **ev, u32 flag, u32 *err);
static int  (*kpep_config_kpc_classes)(kpep_config *cfg, u32 *out);
static int  (*kpep_config_kpc_count)(kpep_config *cfg, usize *out);
static int  (*kpep_config_kpc_map)(kpep_config *cfg, usize *buf, usize size);
static int  (*kpep_config_kpc)(kpep_config *cfg, u64 *buf, usize size);
static const char *(*kpep_strerror)(int err);

#define KPERF_PATH     "/System/Library/PrivateFrameworks/kperf.framework/kperf"
#define KPERFDATA_PATH "/System/Library/PrivateFrameworks/kperfdata.framework/kperfdata"

// --- Small utilities ----------------------------------------------------------

static void die(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "simple_perf: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

static void *xcalloc(usize n, usize size) {
    void *p = calloc(n, size);
    if (!p) die("out of memory");
    return p;
}

static void *xrealloc(void *p, usize size) {
    p = realloc(p, size);
    if (!p) die("out of memory");
    return p;
}

static u64 now_ns(void) { return clock_gettime_nsec_np(CLOCK_UPTIME_RAW); }

// rusage_info times are mach absolute time units (24 MHz ticks on Apple Silicon).
static double abs_to_ns(u64 t) {
    static mach_timebase_info_data_t tb;
    if (!tb.denom) mach_timebase_info(&tb);
    return (double)t * tb.numer / tb.denom;
}

// 1234567 -> "1,234,567". Rotating static buffers so several fit in one printf.
static const char *commas(double v) {
    static char bufs[8][40];
    static int k;
    char *out = bufs[k++ & 7], tmp[40];
    snprintf(tmp, sizeof(tmp), "%.0f", v);
    int len = (int)strlen(tmp), o = 0, start = (tmp[0] == '-');
    for (int i = 0; i < len; i++) {
        if (i > start && (len - i) % 3 == 0) out[o++] = ',';
        out[o++] = tmp[i];
    }
    out[o] = 0;
    return out;
}

static int sysctl_int(const char *name) {
    int v = 0;
    usize len = sizeof(v);
    return sysctlbyname(name, &v, &len, NULL, 0) ? 0 : v;
}

static volatile sig_atomic_t g_stop;
static void on_sigint(int sig) { (void)sig; g_stop = 1; }

static void catch_sigint(void) {
    struct sigaction sa = {0};
    sa.sa_handler = on_sigint;  // no SA_RESTART: let usleep/waitid return early
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

static pid_t spawn_cmd(char **argv, bool suspended) {
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    if (suspended) posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
    pid_t pid;
    int r = posix_spawnp(&pid, argv[0], NULL, &attr, argv, environ);
    posix_spawnattr_destroy(&attr);
    if (r) die("cannot run '%s': %s", argv[0], strerror(r));
    return pid;
}

// True once the child has exited; leaves it as a zombie so rusage stays readable.
static bool child_exited(pid_t pid, bool block) {
    siginfo_t si = {0};
    int flags = WEXITED | WNOWAIT | (block ? 0 : WNOHANG);
    while (waitid(P_PID, (id_t)pid, &si, flags) < 0) {
        if (errno != EINTR) return true;
        if (!block) return false;
    }
    return si.si_pid == pid;
}

// --- Framework loading & PMU ownership ------------------------------------------

#define LOAD(lib, sym) do {                                             \
    *(void **)&sym = dlsym(lib, #sym);                                  \
    if (!sym) die("dlsym %s failed (unsupported macOS version?)", #sym); \
} while (0)

static void load_frameworks(void) {
    static bool loaded;
    if (loaded) return;
    void *kperf     = dlopen(KPERF_PATH,     RTLD_LAZY);
    void *kperfdata = dlopen(KPERFDATA_PATH, RTLD_LAZY);
    if (!kperf || !kperfdata) die("dlopen failed: %s", dlerror());

    LOAD(kperf, kpc_force_all_ctrs_get);
    LOAD(kperf, kpc_force_all_ctrs_set);
    LOAD(kperf, kpc_get_counter_count);
    LOAD(kperf, kpc_get_config_count);
    LOAD(kperf, kpc_set_config);
    LOAD(kperf, kpc_set_counting);
    LOAD(kperf, kpc_set_thread_counting);
    LOAD(kperf, kpc_get_thread_counters);
    LOAD(kperf, kpc_get_cpu_counters);
    LOAD(kperf, kpc_cpu_string);
    LOAD(kperf, kperf_reset);
    LOAD(kperf, kperf_sample_set);
    LOAD(kperf, kperf_action_count_set);
    LOAD(kperf, kperf_action_samplers_set);
    LOAD(kperf, kperf_action_filter_set_by_pid);
    LOAD(kperf, kperf_timer_count_set);
    LOAD(kperf, kperf_timer_period_set);
    LOAD(kperf, kperf_timer_action_set);
    LOAD(kperf, kperf_ns_to_ticks);

    LOAD(kperfdata, kpep_db_create);
    LOAD(kperfdata, kpep_db_name);
    LOAD(kperfdata, kpep_db_events_count);
    LOAD(kperfdata, kpep_db_events);
    LOAD(kperfdata, kpep_config_create);
    LOAD(kperfdata, kpep_config_force_counters);
    LOAD(kperfdata, kpep_config_add_event);
    LOAD(kperfdata, kpep_config_kpc_classes);
    LOAD(kperfdata, kpep_config_kpc_count);
    LOAD(kperfdata, kpep_config_kpc_map);
    LOAD(kperfdata, kpep_config_kpc);
    LOAD(kperfdata, kpep_strerror);
    loaded = true;
}

static kpep_db     *g_db;
static kpep_event **g_events;
static usize        g_nevents;
static u32          g_nfixed, g_nconfig;   // counter slots: [0, nfixed) fixed, then configurable

static void open_db(void) {
    load_frameworks();
    if (g_db) return;
    int r = kpep_db_create(NULL, &g_db);
    if (r) die("kpep_db_create: %s (Intel Mac?)", kpep_strerror(r));
    kpep_db_events_count(g_db, &g_nevents);
    g_events = xcalloc(g_nevents, sizeof(*g_events));
    if (kpep_db_events(g_db, g_events, g_nevents * sizeof(*g_events)))
        die("kpep_db_events failed");
    g_nfixed  = kpc_get_counter_count(KPC_CLASS_FIXED_MASK);
    g_nconfig = kpc_get_counter_count(KPC_CLASS_CONFIGURABLE_MASK);
}

static pid_t g_child;            // spawned and not yet reaped
static bool  g_pmu_owned;
static int   g_saved_force;
static bool  g_kperf_active;
static bool  g_kdebug_active;
static void  kdebug_stop(void);

// Leave the machine as we found it, however we exit.
static void cleanup(void) {
    if (g_kperf_active) {
        kperf_sample_set(0);
        kperf_reset();
        g_kperf_active = false;
    }
    if (g_kdebug_active) kdebug_stop();
    if (g_pmu_owned) {
        kpc_set_counting(0);
        kpc_set_thread_counting(0);
        kpc_force_all_ctrs_set(g_saved_force);
        g_pmu_owned = false;
    }
    if (g_child > 0) {
        kill(g_child, SIGKILL);
        waitpid(g_child, NULL, 0);
        g_child = 0;
    }
}

static void pmu_acquire(void) {
    load_frameworks();
    // kpc_force_all_ctrs_get only succeeds as root.
    if (kpc_force_all_ctrs_get(&g_saved_force))
        die("programming the PMU needs root: run with sudo");
    // Take all counters away from the OS power manager while we use them.
    if (kpc_force_all_ctrs_set(1)) die("kpc_force_all_ctrs_set failed");
    g_pmu_owned = true;
}

// --- Event specs & counter groups ------------------------------------------------

// perf's generic names -> Apple event names (M-series naming).
static const struct { const char *alias, *name; } perf_aliases[] = {
    { "cycles",                  "FIXED_CYCLES" },
    { "cpu-cycles",              "FIXED_CYCLES" },
    { "instructions",            "FIXED_INSTRUCTIONS" },
    { "branches",                "INST_BRANCH" },
    { "branch-instructions",     "INST_BRANCH" },
    { "branch-misses",           "BRANCH_MISPRED_NONSPEC" },
    { "L1-dcache-load-misses",   "L1D_CACHE_MISS_LD_NONSPEC" },
    { "L1-dcache-store-misses",  "L1D_CACHE_MISS_ST_NONSPEC" },
    { "L1-icache-load-misses",   "L1I_CACHE_MISS_DEMAND" },
    { "dTLB-load-misses",        "L1D_TLB_MISS_NONSPEC" },
    { "iTLB-load-misses",        "L1I_TLB_MISS_DEMAND" },
    { "stalled-cycles-frontend", "ARM_STALL_FRONTEND" },
    { "stalled-cycles-backend",  "ARM_STALL_BACKEND" },
    { "uops-retired",            "RETIRE_UOP" },
};

// `stat -d` / `bench` default set, mirroring perf stat -d.
static const char *detailed_events[] = {
    "branches", "branch-misses", "L1-dcache-load-misses", "L1-icache-load-misses",
    "stalled-cycles-frontend", "stalled-cycles-backend",
};

typedef struct {
    char        label[64];   // what we print (user's spelling + modifier)
    kpep_event *ev;
    u32         flag;        // kpep add_event flag: 1 = user space only
    bool        kernel_only; // `:k`, applied by hand to the config word
    int         group;       // -1 for the always-on fixed counters
    usize       cfg_index;   // index within its group's kpep_config
} event_spec;

typedef struct {
    kpep_config *cfg;
    usize nev;               // events added to cfg, including the 2 fixed ones
    u32   classes;
    u64   regs[KPC_MAX_COUNTERS];
    usize map[KPC_MAX_COUNTERS];  // cfg event index -> counter slot
} counter_group;

static kpep_event *find_event(const char *name) {
    for (usize i = 0; i < sizeof(perf_aliases) / sizeof(perf_aliases[0]); i++)
        if (!strcasecmp(name, perf_aliases[i].alias)) { name = perf_aliases[i].name; break; }
    for (usize i = 0; i < g_nevents; i++) {
        kpep_event *ev = g_events[i];
        if (!strcasecmp(ev->name, name) || (ev->alias && !strcasecmp(ev->alias, name))) return ev;
    }
    return NULL;
}

static bool add_spec(event_spec *specs, int *n, const char *token, bool quiet) {
    if (*n >= MAX_EVENTS) die("too many events (max %d)", MAX_EVENTS);
    char name[64];
    snprintf(name, sizeof(name), "%s", token);
    event_spec *s = &specs[*n];
    memset(s, 0, sizeof(*s));
    char *mod = strchr(name, ':');
    if (mod) {
        *mod++ = 0;
        if (!strcmp(mod, "u"))      s->flag = 1;
        else if (!strcmp(mod, "k")) s->kernel_only = true;
        else die("unknown modifier ':%s' on %s (use :u or :k)", mod, name);
    }
    s->ev = find_event(name);
    if (!s->ev) {
        if (quiet) return false;
        die("unknown event '%s' (see `simple_perf list`)", name);
    }
    if (s->ev->is_fixed && (s->flag || s->kernel_only))
        die("%s is a fixed counter; :u/:k modifiers need a configurable event", name);
    snprintf(s->label, sizeof(s->label), "%s", token);
    (*n)++;
    return true;
}

static void parse_event_list(const char *list, event_spec *specs, int *n) {
    char *copy = strdup(list), *save = NULL;
    for (char *tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save))
        if (*tok) add_spec(specs, n, tok, false);
    free(copy);
}

static int add_to_config(kpep_config *cfg, kpep_event *ev, u32 flag) {
    u32 err = 0;
    return kpep_config_add_event(cfg, &ev, flag, &err);
}

static kpep_config *new_config(void) {
    kpep_config *cfg = NULL;
    if (kpep_config_create(g_db, &cfg) || kpep_config_force_counters(cfg))
        die("kpep_config_create failed");
    // Every group carries cycles + instructions so derived metrics always work.
    kpep_event *cyc = find_event("FIXED_CYCLES"), *ins = find_event("FIXED_INSTRUCTIONS");
    if (!cyc || !ins || add_to_config(cfg, cyc, 0) || add_to_config(cfg, ins, 0))
        die("fixed cycle/instruction counters unavailable");
    return cfg;
}

// Pack events into as few counter groups as possible (first fit). More than
// one group means we multiplex: groups take turns on the hardware.
static int build_groups(event_spec *specs, int n, counter_group *groups) {
    int ng = 0;
    for (int i = 0; i < n; i++) {
        event_spec *s = &specs[i];
        if (s->ev->is_fixed) {
            s->group = -1;
            s->cfg_index = strstr(s->ev->name, "CYCLES") ? 0 : 1;
            continue;
        }
        int g;
        for (g = 0; g < ng; g++) {
            int r = add_to_config(groups[g].cfg, s->ev, s->flag);
            if (r == 0) break;
            if (r != KPEP_ERR_CONFLICT) die("%s: %s", s->label, kpep_strerror(r));
        }
        if (g == ng) {
            if (ng == MAX_EVENTS) die("too many counter groups");
            groups[ng].cfg = new_config();
            groups[ng].nev = 2;
            int r = add_to_config(groups[ng].cfg, s->ev, s->flag);
            if (r) die("%s cannot be scheduled: %s", s->label, kpep_strerror(r));
            ng++;
        }
        s->group = g;
        s->cfg_index = groups[g].nev++;
    }
    if (ng == 0) {  // only fixed events requested: one group with just those
        groups[0].cfg = new_config();
        groups[0].nev = 2;
        ng = 1;
    }

    // Ask kpep to translate each group's event list into (a) the counter
    // classes it needs, (b) raw per-register config values, (c) a map from
    // event index -> hardware counter slot.
    for (int g = 0; g < ng; g++) {
        counter_group *cg = &groups[g];
        usize reg_count = 0;
        if (kpep_config_kpc_classes(cg->cfg, &cg->classes) ||
            kpep_config_kpc_count(cg->cfg, &reg_count) ||
            kpep_config_kpc_map(cg->cfg, cg->map, sizeof(cg->map)) ||
            kpep_config_kpc(cg->cfg, cg->regs, sizeof(cg->regs)))
            die("kpc config extract failed");
    }
    // `:k` isn't exposed by kpep, so flip the mode bits in the config word.
    for (int i = 0; i < n; i++) {
        if (!specs[i].kernel_only) continue;
        counter_group *cg = &groups[specs[i].group];
        u64 *reg = &cg->regs[cg->map[specs[i].cfg_index] - g_nfixed];
        *reg = (*reg & ~CFG_EL0) | CFG_EL1;
    }
    return ng;
}

static void program_group(counter_group *g, bool thread) {
    if ((g->classes & KPC_CLASS_CONFIGURABLE_MASK) && kpc_set_config(g->classes, g->regs))
        die("kpc_set_config failed");
    if (kpc_set_counting(g->classes)) die("kpc_set_counting failed");
    if (thread && kpc_set_thread_counting(g->classes)) die("kpc_set_thread_counting failed");
}

// Sum every counter across all CPUs.
static void read_system_counters(u32 classes, u64 out[KPC_MAX_COUNTERS]) {
    static u64 buf[KPC_MAX_CPUS * KPC_MAX_COUNTERS];
    u32 nctr = kpc_get_counter_count(classes);
    int ncpu = sysctl_int("hw.ncpu");
    if (ncpu <= 0 || ncpu > KPC_MAX_CPUS) ncpu = KPC_MAX_CPUS;
    if (kpc_get_cpu_counters(1, classes, NULL, buf)) die("kpc_get_cpu_counters failed");
    memset(out, 0, KPC_MAX_COUNTERS * sizeof(u64));
    for (int c = 0; c < ncpu; c++)
        for (u32 i = 0; i < nctr && i < KPC_MAX_COUNTERS; i++)
            out[i] += buf[c * nctr + i];
}

static void read_thread_counters(u32 classes, u64 out[KPC_MAX_COUNTERS]) {
    memset(out, 0, KPC_MAX_COUNTERS * sizeof(u64));
    if (kpc_get_thread_counters(0, kpc_get_counter_count(classes), out))
        die("kpc_get_thread_counters failed");
}

// --- Derived metrics (the "# ..." column) -----------------------------------------

typedef struct {
    double cycles, instructions, branches, seconds;
} metric_ctx;

static void event_comment(const kpep_event *ev, double v, const metric_ctx *m, char *out, usize n) {
    const char *name = ev->name, *desc = ev->description ? ev->description : "";
    out[0] = 0;
    if (!strcmp(name, "FIXED_CYCLES")) {
        if (m->seconds > 0) snprintf(out, n, "%8.3f GHz", v / m->seconds / 1e9);
    } else if (!strcmp(name, "FIXED_INSTRUCTIONS")) {
        if (m->cycles > 0) snprintf(out, n, "%8.2f  insn per cycle", v / m->cycles);
    } else if (strstr(name, "MISPRED") && m->branches > 0) {
        snprintf(out, n, "%8.2f%% of all branches", 100.0 * v / m->branches);
    } else if (!strncmp(name, "INST_", 5) && m->instructions > 0) {
        snprintf(out, n, "%8.2f%% of instructions", 100.0 * v / m->instructions);
    } else if (strstr(name, "_SLOT") && m->cycles > 0) {
        snprintf(out, n, "%8.2f per cycle", v / m->cycles);
    } else if ((strstr(name, "STALL") || strstr(name, "BUBBLE") || !strncmp(desc, "Cycles", 6)) && m->cycles > 0) {
        snprintf(out, n, "%8.2f%% of cycles", 100.0 * v / m->cycles);
    } else if ((strstr(name, "MISS") || strstr(name, "FILL") || strstr(name, "WALK")) && m->instructions > 0) {
        snprintf(out, n, "%8.2f per 1k insn", 1000.0 * v / m->instructions);
    } else if (m->instructions > 0) {
        snprintf(out, n, "%8.3f per insn", v / m->instructions);
    }
}

// Build metric context from a spec list + counts (branches only if counted).
static metric_ctx make_ctx(event_spec *specs, int n, const double *counts,
                           double cycles, double instructions, double seconds) {
    metric_ctx m = { cycles, instructions, 0, seconds };
    for (int i = 0; i < n; i++)
        if (!strcmp(specs[i].ev->name, "INST_BRANCH")) m.branches = counts[i];
    return m;
}

// --- list -----------------------------------------------------------------------

static void mask_str(u32 mask, char *out, usize n) {
    u32 all = ((1u << g_nconfig) - 1) << g_nfixed;
    if ((mask & all) == all) { snprintf(out, n, "any"); return; }
    out[0] = 0;
    for (int b = 0; b < 32; b++) {
        if (!(mask & (1u << b))) continue;
        int e = b;
        while (e + 1 < 32 && (mask & (1u << (e + 1)))) e++;
        usize len = strlen(out);
        if (e == b) snprintf(out + len, n - len, "%s%d", len ? "," : "", b);
        else        snprintf(out + len, n - len, "%s%d-%d", len ? "," : "", b, e);
        b = e;
    }
}

static int cmd_list(int argc, char **argv) {
    open_db();
    const char *pat = argc > 1 ? argv[1] : NULL;
    const char *dbname = "?";
    kpep_db_name(g_db, &dbname);

    printf("perf-style aliases:\n");
    for (usize i = 0; i < sizeof(perf_aliases) / sizeof(perf_aliases[0]); i++) {
        if (pat && !strcasestr(perf_aliases[i].alias, pat) && !strcasestr(perf_aliases[i].name, pat)) continue;
        bool ok = find_event(perf_aliases[i].name) != NULL;
        printf("  %-26s -> %s%s\n", perf_aliases[i].alias, perf_aliases[i].name, ok ? "" : "  (not on this CPU)");
    }
    printf("\n%s PMU events (%u fixed + %u configurable counters; slot column = allowed counters):\n",
           dbname, g_nfixed, g_nconfig);
    for (usize i = 0; i < g_nevents; i++) {
        kpep_event *ev = g_events[i];
        const char *desc = ev->description ? ev->description : (ev->alias ? ev->alias : "");
        if (pat && !strcasestr(ev->name, pat) && !strcasestr(desc, pat)) continue;
        char slots[32];
        if (ev->is_fixed) snprintf(slots, sizeof(slots), "fixed");
        else mask_str(ev->counters_mask, slots, sizeof(slots));
        printf("  %-40s %-6s %s\n", ev->name, slots, desc);
    }
    printf("\nModifiers: NAME:u (user only), NAME:k (kernel only). Names are case-insensitive.\n");
    return 0;
}

// --- info -----------------------------------------------------------------------

static int cmd_info(void) {
    open_db();
    char cpu[64] = {0}, brand[128] = {0};
    usize len = sizeof(brand);
    kpc_cpu_string(cpu, sizeof(cpu));
    sysctlbyname("machdep.cpu.brand_string", brand, &len, NULL, 0);
    const char *dbname = "?";
    kpep_db_name(g_db, &dbname);
    printf("cpu:            %s (%s)\n", brand, cpu);
    printf("cores:          %d P + %d E\n", sysctl_int("hw.perflevel0.logicalcpu"), sysctl_int("hw.perflevel1.logicalcpu"));
    printf("event database: %s, %zu events (/usr/share/kpep/%s.plist)\n", dbname, g_nevents, cpu);
    printf("counters:       %u fixed + %u configurable, %u config registers\n",
           g_nfixed, g_nconfig, kpc_get_config_count(KPC_CLASS_CONFIGURABLE_MASK));
    int forced = 0;
    if (kpc_force_all_ctrs_get(&forced) == 0)
        printf("force_all_ctrs: %d (1 = counters held by a profiler)\n", forced);
    else
        printf("force_all_ctrs: (needs root to read)\n");
    return 0;
}

// --- stat -----------------------------------------------------------------------

typedef struct { double sum, sumsq; int n; } running_stat;

static void rs_add(running_stat *r, double v) { r->sum += v; r->sumsq += v * v; r->n++; }
static double rs_mean(const running_stat *r) { return r->n ? r->sum / r->n : 0; }
// perf's "( +- x% )": standard error of the mean, relative.
static double rs_noise_pct(const running_stat *r) {
    if (r->n < 2) return 0;
    double mean = rs_mean(r);
    double var = (r->sumsq - r->n * mean * mean) / (r->n - 1);
    if (var < 0 || mean == 0) return 0;
    return 100.0 * sqrt(var / r->n) / fabs(mean);
}

enum {
    M_WALL, M_USER, M_SYS, M_CSW, M_FAULTS, M_CYC, M_INS, M_PCYC, M_PINS, M_ENERGY, M_PENERGY,
    M_SW_CYC, M_SW_INS, M_SW_TIME, M_COUNT
};

typedef struct {
    event_spec    specs[MAX_EVENTS];
    int           nspecs;
    counter_group groups[MAX_EVENTS];
    int           ngroups;           // 0 = no PMU programming (rusage only)
    int           repeat;
    u64           interval_ns;
    u64           duration_ns;
    pid_t         attach_pid;
    char        **cmd;
    running_stat  m[M_COUNT];
    running_stat  ev[MAX_EVENTS];    // scaled system-wide counts
    double        ev_enabled[MAX_EVENTS];  // fraction of time each event was live
} stat_state;

// Raw accumulation for one measurement window (whole run, or one -I interval).
typedef struct {
    u64 raw[MAX_EVENTS];
    u64 enabled_ns[MAX_EVENTS];
    u64 cycles, instructions, live_ns;
} window;

// Close a multiplexing segment for group `g`: credit counter deltas to its events.
static void credit_segment(stat_state *st, int g, const u64 *start, const u64 *end, u64 ns,
                           window **wins, int nwins) {
    counter_group *cg = &st->groups[g];
    for (int w = 0; w < nwins; w++) {
        window *win = wins[w];
        win->cycles       += end[cg->map[0]] - start[cg->map[0]];
        win->instructions += end[cg->map[1]] - start[cg->map[1]];
        win->live_ns      += ns;
        for (int i = 0; i < st->nspecs; i++) {
            event_spec *s = &st->specs[i];
            if (s->group != g && s->group != -1) continue;
            usize slot = cg->map[s->cfg_index];
            win->raw[i]        += end[slot] - start[slot];
            win->enabled_ns[i] += ns;
        }
    }
}

// Scale a multiplexed count up to the full window, like perf does.
static double scaled(const window *w, int i, u64 total_ns) {
    if (!w->enabled_ns[i]) return 0;
    return (double)w->raw[i] * total_ns / w->enabled_ns[i];
}

static void print_interval(stat_state *st, const window *w, double t_sec, u64 span_ns) {
    double sc = w->live_ns ? (double)span_ns / w->live_ns : 1;
    fprintf(stderr, "%14.6f %19s      %s\n", t_sec, commas(w->cycles * sc), "cycles");
    fprintf(stderr, "%14.6f %19s      %s\n", t_sec, commas(w->instructions * sc), "instructions");
    for (int i = 0; i < st->nspecs; i++) {
        if (st->specs[i].group == -1) continue;
        fprintf(stderr, "%14.6f %19s      %s\n", t_sec, commas(scaled(w, i, span_ns)), st->specs[i].label);
    }
}

#define MUX_INTERVAL_NS (10ull * 1000 * 1000)

static void stat_once(stat_state *st, bool first) {
    bool sw = st->ngroups > 0;
    window total = {0}, iv = {0};
    window *both[2] = { &total, &iv };
    int nwins = st->interval_ns ? 2 : 1;
    u64 start[KPC_MAX_COUNTERS], end[KPC_MAX_COUNTERS];
    int cur = 0;
    u32 classes = sw ? st->groups[0].classes : 0;

    struct rusage_info_v6 ru0 = {0}, ru1 = {0};
    if (sw) {
        program_group(&st->groups[0], false);
        read_system_counters(classes, start);
    }

    u64 t0 = now_ns(), seg_t0 = t0, iv_t0 = t0;
    pid_t pid = 0;
    if (st->cmd) {
        pid = g_child = spawn_cmd(st->cmd, false);
    } else if (st->attach_pid) {
        pid = st->attach_pid;
        if (proc_pid_rusage(pid, RUSAGE_INFO_V6, (rusage_info_t *)&ru0))
            die("cannot read pid %d: %s", pid, strerror(errno));
        ru1 = ru0;
    }

    bool poll = !st->cmd || (sw && (st->ngroups > 1 || st->interval_ns));
    if (!poll) {
        child_exited(pid, true);
    } else {
        u64 next_rot = t0 + MUX_INTERVAL_NS, next_iv = t0 + st->interval_ns;
        for (;;) {
            if (st->cmd) {
                if (child_exited(pid, false)) break;
            } else {
                if (g_stop) break;
                if (pid && proc_pid_rusage(pid, RUSAGE_INFO_V6, (rusage_info_t *)&ru1)) break;  // exited
            }
            u64 t = now_ns();
            if (st->duration_ns && t - t0 >= st->duration_ns) break;
            usleep(1000);
            t = now_ns();
            if (!sw) continue;
            bool rotate = st->ngroups > 1 && t >= next_rot;
            bool tick   = st->interval_ns && t >= next_iv;
            if (!rotate && !tick) continue;
            read_system_counters(classes, end);
            credit_segment(st, cur, start, end, t - seg_t0, both, nwins);
            if (tick) {
                print_interval(st, &iv, (t - t0) / 1e9, t - iv_t0);
                memset(&iv, 0, sizeof(iv));
                iv_t0 = t;
                next_iv += st->interval_ns;
            }
            if (rotate) {
                cur = (cur + 1) % st->ngroups;
                program_group(&st->groups[cur], false);
                next_rot = t + MUX_INTERVAL_NS;
            }
            read_system_counters(classes, start);
            seg_t0 = now_ns();
        }
    }
    u64 t1 = now_ns();
    if (sw) {
        read_system_counters(classes, end);
        credit_segment(st, cur, start, end, t1 - seg_t0, both, nwins);
    }

    double user_ns = 0, sys_ns = 0;
    if (st->cmd) {
        // The child is a zombie now: its kernel-maintained rusage is still readable.
        proc_pid_rusage(pid, RUSAGE_INFO_V6, (rusage_info_t *)&ru1);
        int status;
        struct rusage ru;
        wait4(pid, &status, 0, &ru);
        g_child = 0;
        rs_add(&st->m[M_CSW], ru.ru_nvcsw + ru.ru_nivcsw);
        rs_add(&st->m[M_FAULTS], ru.ru_minflt + ru.ru_majflt);
        if (first && WIFSIGNALED(status))
            fprintf(stderr, "simple_perf: '%s' killed by signal %d\n", st->cmd[0], WTERMSIG(status));
        else if (first && WIFEXITED(status) && WEXITSTATUS(status))
            fprintf(stderr, "simple_perf: '%s' exited with status %d\n", st->cmd[0], WEXITSTATUS(status));
    }
    if (pid) {
        user_ns = abs_to_ns(ru1.ri_user_time - ru0.ri_user_time);
        sys_ns  = abs_to_ns(ru1.ri_system_time - ru0.ri_system_time);
        rs_add(&st->m[M_USER], user_ns);
        rs_add(&st->m[M_SYS], sys_ns);
        rs_add(&st->m[M_CYC], ru1.ri_cycles - ru0.ri_cycles);
        rs_add(&st->m[M_INS], ru1.ri_instructions - ru0.ri_instructions);
        rs_add(&st->m[M_PCYC], ru1.ri_pcycles - ru0.ri_pcycles);
        rs_add(&st->m[M_PINS], ru1.ri_pinstructions - ru0.ri_pinstructions);
        rs_add(&st->m[M_ENERGY], ru1.ri_energy_nj - ru0.ri_energy_nj);
        rs_add(&st->m[M_PENERGY], ru1.ri_penergy_nj - ru0.ri_penergy_nj);
    }
    rs_add(&st->m[M_WALL], t1 - t0);
    if (sw) {
        u64 span = t1 - t0;
        double sc = total.live_ns ? (double)span / total.live_ns : 1;
        rs_add(&st->m[M_SW_CYC], total.cycles * sc);
        rs_add(&st->m[M_SW_INS], total.instructions * sc);
        rs_add(&st->m[M_SW_TIME], span);
        for (int i = 0; i < st->nspecs; i++) {
            rs_add(&st->ev[i], st->specs[i].group == -1
                   ? (st->specs[i].cfg_index == 0 ? total.cycles : total.instructions) * sc
                   : scaled(&total, i, span));
            st->ev_enabled[i] = span ? (double)total.enabled_ns[i] / span : 0;
        }
    }
}

static void print_line(const char *value, const char *name, const char *comment,
                       const running_stat *r, double enabled) {
    fprintf(stderr, "%19s      %-26s", value, name);
    if (comment && *comment) fprintf(stderr, " # %s", comment);
    if (r && r->n > 1) fprintf(stderr, "  ( +-%6.2f%% )", rs_noise_pct(r));
    if (enabled > 0 && enabled < 0.999) fprintf(stderr, "  (%.2f%%)", 100 * enabled);
    fprintf(stderr, "\n");
}

static void print_stat(stat_state *st) {
    char comment[96], value[48];
    double wall = rs_mean(&st->m[M_WALL]) / 1e9;
    bool proc = st->cmd || st->attach_pid;

    fprintf(stderr, "\n Performance counter stats for ");
    if (st->cmd) {
        fprintf(stderr, "'");
        for (char **a = st->cmd; *a; a++) fprintf(stderr, "%s%s", a == st->cmd ? "" : " ", *a);
        fprintf(stderr, "'");
    } else if (st->attach_pid) {
        fprintf(stderr, "process id '%d'", st->attach_pid);
    } else {
        fprintf(stderr, "'system wide'");
    }
    if (st->repeat > 1) fprintf(stderr, " (%d runs)", st->repeat);
    fprintf(stderr, ":\n\n");

    if (proc) {
        double task = (rs_mean(&st->m[M_USER]) + rs_mean(&st->m[M_SYS])) / 1e9;
        double cyc = rs_mean(&st->m[M_CYC]), ins = rs_mean(&st->m[M_INS]);
        double pcyc = rs_mean(&st->m[M_PCYC]), pins = rs_mean(&st->m[M_PINS]);

        snprintf(value, sizeof(value), "%.2f msec", task * 1e3);
        snprintf(comment, sizeof(comment), "%8.3f CPUs utilized", wall > 0 ? task / wall : 0);
        print_line(value, "task-clock", comment, &st->m[M_USER], 0);
        if (st->cmd) {
            double csw = rs_mean(&st->m[M_CSW]), flt = rs_mean(&st->m[M_FAULTS]);
            snprintf(comment, sizeof(comment), "%8.3f K/sec", task > 0 ? csw / task / 1e3 : 0);
            print_line(commas(csw), "context-switches", comment, &st->m[M_CSW], 0);
            snprintf(comment, sizeof(comment), "%8.3f K/sec", task > 0 ? flt / task / 1e3 : 0);
            print_line(commas(flt), "page-faults", comment, &st->m[M_FAULTS], 0);
        }
        snprintf(comment, sizeof(comment), "%8.3f GHz", task > 0 ? cyc / task / 1e9 : 0);
        print_line(commas(cyc), "cycles", comment, &st->m[M_CYC], 0);
        snprintf(comment, sizeof(comment), "%8.2f%% of cycles", cyc > 0 ? 100 * pcyc / cyc : 0);
        print_line(commas(pcyc), "  cycles on P-cores", comment, &st->m[M_PCYC], 0);
        snprintf(comment, sizeof(comment), "%8.2f  insn per cycle", cyc > 0 ? ins / cyc : 0);
        print_line(commas(ins), "instructions", comment, &st->m[M_INS], 0);
        if (pcyc > 0 && cyc - pcyc > 0) {
            snprintf(comment, sizeof(comment), "%8.2f IPC P-core, %.2f IPC E-core",
                     pins / pcyc, (ins - pins) / (cyc - pcyc));
            print_line("", "", comment, NULL, 0);
        }
        double joules = rs_mean(&st->m[M_ENERGY]) / 1e9;
        snprintf(value, sizeof(value), "%.3f J", joules);
        snprintf(comment, sizeof(comment), "%8.3f W avg, %.0f%% on P-cores", wall > 0 ? joules / wall : 0,
                 joules > 0 ? 100 * rs_mean(&st->m[M_PENERGY]) / 1e9 / joules : 0);
        print_line(value, "cpu-energy", comment, &st->m[M_ENERGY], 0);
    }

    if (st->ngroups) {
        double counts[MAX_EVENTS];
        for (int i = 0; i < st->nspecs; i++) counts[i] = rs_mean(&st->ev[i]);
        double cyc = rs_mean(&st->m[M_SW_CYC]), ins = rs_mean(&st->m[M_SW_INS]);
        metric_ctx m = make_ctx(st->specs, st->nspecs, counts, cyc, ins, 0);
        if (proc)
            fprintf(stderr, "\n  system-wide, all %d CPUs (kpc has no per-process configurable counting)%s:\n\n",
                    sysctl_int("hw.ncpu"), st->ngroups > 1 ? ", multiplexed" : "");
        snprintf(comment, sizeof(comment), "%8.3f GHz/CPU avg",
                 wall > 0 ? cyc / wall / sysctl_int("hw.ncpu") / 1e9 : 0);
        print_line(commas(cyc), "cycles", comment, &st->m[M_SW_CYC], 0);
        snprintf(comment, sizeof(comment), "%8.2f  insn per cycle", cyc > 0 ? ins / cyc : 0);
        print_line(commas(ins), "instructions", comment, &st->m[M_SW_INS], 0);
        for (int i = 0; i < st->nspecs; i++) {
            if (st->specs[i].group == -1) continue;
            event_comment(st->specs[i].ev, counts[i], &m, comment, sizeof(comment));
            print_line(commas(counts[i]), st->specs[i].label, comment, &st->ev[i], st->ev_enabled[i]);
        }
    }

    fprintf(stderr, "\n %14.9f seconds time elapsed", wall);
    if (st->repeat > 1) fprintf(stderr, "  ( +-%6.2f%% )", rs_noise_pct(&st->m[M_WALL]));
    fprintf(stderr, "\n");
    if (proc) {
        fprintf(stderr, "\n %14.9f seconds user\n", rs_mean(&st->m[M_USER]) / 1e9);
        fprintf(stderr, " %14.9f seconds sys\n", rs_mean(&st->m[M_SYS]) / 1e9);
    }
    fprintf(stderr, "\n");
}

static void stat_usage(void) {
    fprintf(stderr,
        "usage: simple_perf stat [options] [--] <command> [args...]\n"
        "       simple_perf stat [options] -p <pid>\n"
        "       sudo simple_perf stat -a [options]        (until Ctrl-C)\n\n"
        "  -e ev1,ev2,...  events to count (implies -a; see `simple_perf list`)\n"
        "  -d              add a detailed default set (branches, misses, stalls)\n"
        "  -a              count system-wide on all CPUs (root)\n"
        "  -r N            repeat the command N times, report mean and noise\n"
        "  -I ms           print counts every ms milliseconds (with -a/-e)\n"
        "  -p pid          attach to a running process (Ctrl-C to stop)\n"
        "  -t sec          stop after sec seconds (with -p or -a)\n\n"
        "Without -e/-a/-d no root is needed: cycles, instructions, P/E split and\n"
        "energy come from the kernel's per-process accounting (exact, all threads).\n");
    exit(1);
}

static int cmd_stat(int argc, char **argv) {
    static stat_state st;
    st.repeat = 1;
    bool all = false, detailed = false;
    const char *events = NULL;
    int c;
    optind = 1; optreset = 1;
    while ((c = getopt(argc, argv, "+e:dar:I:p:t:h")) != -1) {
        switch (c) {
        case 'e': events = optarg; break;
        case 'd': detailed = true; break;
        case 'a': all = true; break;
        case 'r': st.repeat = atoi(optarg); break;
        case 'I': st.interval_ns = (u64)(atof(optarg) * 1e6); break;
        case 'p': st.attach_pid = atoi(optarg); break;
        case 't': st.duration_ns = (u64)(atof(optarg) * 1e9); break;
        default: stat_usage();
        }
    }
    if (optind < argc) st.cmd = &argv[optind];
    if (!st.cmd && !st.attach_pid && !all && !events && !detailed) stat_usage();
    if (st.cmd && st.attach_pid) die("give either a command or -p, not both");
    if (st.repeat < 1 || (st.repeat > 1 && !st.cmd)) die("-r needs a command");

    if (events || detailed || all) {
        open_db();
        if (detailed)
            for (usize i = 0; i < sizeof(detailed_events) / sizeof(detailed_events[0]); i++)
                add_spec(st.specs, &st.nspecs, detailed_events[i], true);
        if (events) parse_event_list(events, st.specs, &st.nspecs);
        pmu_acquire();
        st.ngroups = build_groups(st.specs, st.nspecs, st.groups);
        if (st.ngroups > 1)
            fprintf(stderr, "simple_perf: %d events need %d counter groups; multiplexing every %llu ms\n",
                    st.nspecs, st.ngroups, MUX_INTERVAL_NS / 1000000);
    } else if (st.interval_ns) {
        die("-I needs -a, -e or -d");
    }

    catch_sigint();  // with a command, ^C reaches the child via the tty; we print and exit after it
    for (int r = 0; r < st.repeat; r++) stat_once(&st, r == 0);
    print_stat(&st);
    return 0;
}

// --- bench ----------------------------------------------------------------------
//
// In-process microbenchmarks measured with per-thread counters: exact counts,
// no multiplexing estimates (each counter group re-runs the workload).

#define BENCH_N (64u << 20)  // bytes for memory-bound workloads

static u8  *g_bytes;
static u64 *g_chain;

static void setup_bytes(bool sorted) {
    if (!g_bytes) g_bytes = malloc(BENCH_N / 4);
    arc4random_buf(g_bytes, BENCH_N / 4);
    if (sorted) {  // counting sort: same data, perfectly predictable branches
        usize hist[256] = {0}, k = 0;
        for (usize i = 0; i < BENCH_N / 4; i++) hist[g_bytes[i]]++;
        for (int v = 0; v < 256; v++) while (hist[v]--) g_bytes[k++] = (u8)v;
    }
}

static void setup_random_bytes(void) { setup_bytes(false); }
static void setup_sorted_bytes(void) { setup_bytes(true); }

static void setup_chain(void) {
    usize n = BENCH_N / sizeof(u64);
    if (!g_chain) g_chain = malloc(BENCH_N);
    for (usize i = 0; i < n; i++) g_chain[i] = i;
    // Sattolo's algorithm: one random cycle through every slot.
    for (usize i = n - 1; i > 0; i--) {
        usize j = arc4random_uniform((u32)i);
        u64 t = g_chain[i]; g_chain[i] = g_chain[j]; g_chain[j] = t;
    }
}

static u64 run_alu(void) {
    u64 sum = 0;
    for (u64 i = 0; i < 200ull * 1000 * 1000; i++) {
        sum += i * 3 + 1;
        __asm__ volatile("" : "+r"(sum));  // keep clang from folding the loop
    }
    return sum;
}

static u64 run_branchy(void) {
    u64 sum = 0;
    for (int rep = 0; rep < 4; rep++)
        for (usize i = 0; i < BENCH_N / 4; i++) {
            if (g_bytes[i] < 128) {
                sum += g_bytes[i];
                __asm__ volatile("");  // forces a real branch instead of csel
            } else {
                sum ^= i;
            }
        }
    return sum;
}

static u64 run_chase(void) {
    u64 p = 0;
    for (usize i = 0; i < 20u * 1000 * 1000; i++) p = g_chain[p];
    return p;
}

static u64 run_stream(void) {
    u64 sum = 0;
    for (int rep = 0; rep < 4; rep++)
        for (usize i = 0; i < BENCH_N / sizeof(u64); i++) sum += g_chain[i];
    return sum;
}

static const struct {
    const char *name, *desc;
    void (*setup)(void);
    u64  (*run)(void);
} benches[] = {
    { "alu",       "dependent integer adds (core-bound)",          NULL,               run_alu },
    { "branchy",   "data-dependent branch on random bytes",        setup_random_bytes, run_branchy },
    { "branchy-sorted", "same branch on sorted bytes (predictable)", setup_sorted_bytes, run_branchy },
    { "chase",     "random pointer chase over 64 MiB (latency)",   setup_chain,        run_chase },
    { "stream",    "sequential sum over 64 MiB (bandwidth)",       setup_chain,        run_stream },
};
#define NBENCH (sizeof(benches) / sizeof(benches[0]))

static int cmd_bench(int argc, char **argv) {
    event_spec specs[MAX_EVENTS];
    counter_group groups[MAX_EVENTS] = {0};
    int nspecs = 0, c;
    const char *events = NULL;
    optind = 1; optreset = 1;
    while ((c = getopt(argc, argv, "+e:h")) != -1) {
        if (c == 'e') events = optarg;
        else {
            fprintf(stderr, "usage: sudo simple_perf bench [-e ev,...] [workload...]\n\nworkloads:\n");
            for (usize i = 0; i < NBENCH; i++) fprintf(stderr, "  %-15s %s\n", benches[i].name, benches[i].desc);
            return 1;
        }
    }
    open_db();
    if (events) parse_event_list(events, specs, &nspecs);
    else
        for (usize i = 0; i < sizeof(detailed_events) / sizeof(detailed_events[0]); i++)
            add_spec(specs, &nspecs, detailed_events[i], true);
    pmu_acquire();
    int ng = build_groups(specs, nspecs, groups);

    for (usize b = 0; b < NBENCH; b++) {
        bool wanted = optind >= argc;
        for (int a = optind; a < argc; a++) wanted |= !strcmp(argv[a], benches[b].name);
        if (!wanted) continue;
        if (benches[b].setup) benches[b].setup();

        double counts[MAX_EVENTS] = {0}, cycles = 0, instructions = 0;
        u64 sink = 0, ns = 0;
        for (int g = 0; g < ng; g++) {
            u64 before[KPC_MAX_COUNTERS], after[KPC_MAX_COUNTERS];
            program_group(&groups[g], true);
            read_thread_counters(groups[g].classes, before);
            u64 t0 = now_ns();
            sink += benches[b].run();
            u64 t1 = now_ns();
            read_thread_counters(groups[g].classes, after);
            if (g == 0) {
                cycles       = after[groups[0].map[0]] - before[groups[0].map[0]];
                instructions = after[groups[0].map[1]] - before[groups[0].map[1]];
                ns = t1 - t0;
            }
            for (int i = 0; i < nspecs; i++) {
                int sg = specs[i].group < 0 ? 0 : specs[i].group;
                if (sg != g) continue;
                usize slot = groups[g].map[specs[i].cfg_index];
                counts[i] = after[slot] - before[slot];
            }
        }

        char comment[96];
        metric_ctx m = make_ctx(specs, nspecs, counts, cycles, instructions, ns / 1e9);
        fprintf(stderr, "\n %s: %s  [%.1f ms, sink %llx]\n\n", benches[b].name, benches[b].desc,
                ns / 1e6, (unsigned long long)(sink & 0xff));
        kpep_event *cyc = find_event("FIXED_CYCLES"), *ins = find_event("FIXED_INSTRUCTIONS");
        event_comment(cyc, cycles, &m, comment, sizeof(comment));
        print_line(commas(cycles), "cycles", comment, NULL, 0);
        event_comment(ins, instructions, &m, comment, sizeof(comment));
        print_line(commas(instructions), "instructions", comment, NULL, 0);
        for (int i = 0; i < nspecs; i++) {
            if (specs[i].group == -1) continue;
            event_comment(specs[i].ev, counts[i], &m, comment, sizeof(comment));
            print_line(commas(counts[i]), specs[i].label, comment, NULL, 0);
        }
    }
    fprintf(stderr, "\n");
    return 0;
}

// --- record: kdebug plumbing --------------------------------------------------------
//
// kperf writes samples into the kernel trace buffer (kdebug) as DBG_PERF
// events. We drive kdebug with the same sysctls kperf's own logging code uses.

#ifndef KERN_KDEBUG
#define KERN_KDEBUG 24
#endif
#define KERN_KDEFLAGS   1
#define KERN_KDENABLE   3
#define KERN_KDSETBUF   4
#define KERN_KDGETBUF   5
#define KERN_KDSETUP    6
#define KERN_KDREMOVE   7
#define KERN_KDSETREG   8
#define KERN_KDREADTR   10
#define KDBG_NOWRAP     0x2
#define KDBG_CLASSTYPE  0x10000

typedef struct {
    u64 timestamp;
    u64 arg1, arg2, arg3, arg4;
    u64 arg5;       // thread id of the thread that emitted the event
    u32 debugid;
    u32 cpuid;
    u64 unused;
} kd_buf;

typedef struct {
    int nkdbufs;
    int nolog;      // nonzero once a NOWRAP buffer filled up and logging stopped
    unsigned int flags;
    int nkdthreads;
    int bufid;
} kbufinfo_t;

typedef struct {
    unsigned int type, value1, value2, value3, value4;
} kd_regtype;

static int kd_ctl(int op, int value, bool has_value) {
    int mib[4] = { CTL_KERN, KERN_KDEBUG, op, value };
    return sysctl(mib, has_value ? 4 : 3, NULL, NULL, NULL, 0);
}

static void kdebug_stop(void) {
    kd_ctl(KERN_KDENABLE, 0, true);
    kd_ctl(KERN_KDREMOVE, 0, false);
    g_kdebug_active = false;
}

static void kdebug_start(int nbufs) {
    kd_ctl(KERN_KDREMOVE, 0, false);
    if (kd_ctl(KERN_KDSETBUF, nbufs, true) || kd_ctl(KERN_KDSETUP, 0, false))
        die("kdebug setup failed: %s (is ktrace/Instruments running?)", strerror(errno));
    g_kdebug_active = true;
    kd_ctl(KERN_KDEFLAGS, KDBG_NOWRAP, true);
    // Only keep DBG_PERF (class 0x25), exactly like kperf's trace_perf_filter().
    kd_regtype reg = { KDBG_CLASSTYPE, 0x25, 0x26, 0, 0 };
    usize len = sizeof(reg);
    int mib[3] = { CTL_KERN, KERN_KDEBUG, KERN_KDSETREG };
    if (sysctl(mib, 3, &reg, &len, NULL, 0)) die("kdebug filter failed: %s", strerror(errno));
    if (kd_ctl(KERN_KDENABLE, 1, true)) die("kdebug enable failed: %s", strerror(errno));
}

// Input is a byte count; the kernel hands back a count of kd_bufs.
static usize kdebug_read(kd_buf *buf, usize max) {
    usize len = max * sizeof(kd_buf);
    int mib[3] = { CTL_KERN, KERN_KDEBUG, KERN_KDREADTR };
    if (sysctl(mib, 3, buf, &len, NULL, 0)) return 0;
    return len;
}

static bool kdebug_dropped(void) {
    kbufinfo_t info = {0};
    usize len = sizeof(info);
    int mib[3] = { CTL_KERN, KERN_KDEBUG, KERN_KDGETBUF };
    return sysctl(mib, 3, &info, &len, NULL, 0) == 0 && info.nolog;
}

// --- record: decoding kperf samples ---------------------------------------------------

// DBG_PERF debug ids, KDBG_CODE(0x25, subclass, code) = 0x25 << 24 | sub << 16 | code << 2.
#define PERF_GEN_EVENT 0x25000000u   // sample start/end, arg1 = samplers, arg2 = action id
#define PERF_TI_DATA   0x25010004u   // thread info: arg1 = pid, arg2 = tid
#define PERF_CS_KDATA  0x2502000cu   // 4 kernel frames per event
#define PERF_CS_UDATA  0x25020010u   // 4 user frames per event
#define PERF_CS_KHDR   0x25020014u   // arg1 = flags, arg2 = nframes, arg4 = async nframes
#define PERF_CS_UHDR   0x25020018u
#define DBG_FUNC_START 1
#define DBG_FUNC_END   2

#define SAMPLER_TH_INFO (1u << 0)
#define SAMPLER_KSTACK  (1u << 2)
#define SAMPLER_USTACK  (1u << 3)

#define REC_ACTION 1
#define MAX_FRAMES 320

typedef struct {
    u64  tid;
    int  pid;
    u32  samples;
    u32  pending;          // timer samples still waiting for their user stack
    u32  pending_kernel;   // ...of which were taken while in the kernel
    bool in_timer, cur_kernel;
    u32  kwant, kgot;
    u32  uwant, ugot;
    u64  uframes[MAX_FRAMES];
} thread_state;

typedef struct {
    u32  hash, n;
    bool kernel;
    u64  count;
    u64 *frames;           // leaf first
} stack_entry;

typedef struct {
    thread_state *threads;
    usize         nthreads;
    stack_entry  *stacks;
    usize         cap, nstacks;
    u64           total, lost;
    u32           raw_ids[256];
    u64           raw_counts[256];
    int           nraw;
    bool          raw;
} rec_state;

static thread_state *thread_get(rec_state *rs, u64 tid) {
    static usize last;
    if (last < rs->nthreads && rs->threads[last].tid == tid) return &rs->threads[last];
    for (usize i = 0; i < rs->nthreads; i++)
        if (rs->threads[i].tid == tid) return &rs->threads[last = i];
    rs->threads = xrealloc(rs->threads, (rs->nthreads + 1) * sizeof(thread_state));
    thread_state *t = &rs->threads[rs->nthreads];
    memset(t, 0, sizeof(*t));
    t->tid = tid;
    last = rs->nthreads++;
    return t;
}

static u32 hash_stack(const u64 *f, u32 n, bool kernel) {
    u32 h = 2166136261u ^ kernel;
    for (u32 i = 0; i < n; i++) { h ^= (u32)f[i] ^ (u32)(f[i] >> 32); h *= 16777619u; }
    return h;
}

static void add_stack(rec_state *rs, const u64 *frames, u32 n, bool kernel, u64 weight) {
    if (rs->nstacks * 10 >= rs->cap * 7) {  // grow & rehash at 70% load
        usize ncap = rs->cap ? rs->cap * 2 : 4096;
        stack_entry *ns = xcalloc(ncap, sizeof(stack_entry));
        for (usize i = 0; i < rs->cap; i++) {
            if (!rs->stacks[i].frames) continue;
            usize j = rs->stacks[i].hash & (ncap - 1);
            while (ns[j].frames) j = (j + 1) & (ncap - 1);
            ns[j] = rs->stacks[i];
        }
        free(rs->stacks);
        rs->stacks = ns;
        rs->cap = ncap;
    }
    u32 h = hash_stack(frames, n, kernel);
    usize j = h & (rs->cap - 1);
    for (; rs->stacks[j].frames; j = (j + 1) & (rs->cap - 1)) {
        stack_entry *e = &rs->stacks[j];
        if (e->hash == h && e->n == n && e->kernel == kernel && !memcmp(e->frames, frames, n * sizeof(u64))) {
            e->count += weight;
            return;
        }
    }
    stack_entry *e = &rs->stacks[j];
    e->hash = h; e->n = n; e->kernel = kernel; e->count = weight;
    e->frames = xcalloc(n ? n : 1, sizeof(u64));
    memcpy(e->frames, frames, n * sizeof(u64));
    rs->nstacks++;
}

// A user stack finished arriving: attribute it to the timer samples it answers.
static void emit_user_stack(rec_state *rs, thread_state *t) {
    u32 n = t->ugot;
    if (n > 1) n--;  // kperf appends the saved LR as a "fixup" word; drop it
    u32 w = t->pending ? t->pending : 1;
    u32 wk = t->pending_kernel < w ? t->pending_kernel : w;
    if (n) {
        if (w - wk) add_stack(rs, t->uframes, n, false, w - wk);
        if (wk)     add_stack(rs, t->uframes, n, true, wk);
        rs->total += w;
    } else {
        rs->lost += w;
    }
    t->samples += w;
    t->pending = t->pending_kernel = 0;
    t->uwant = t->ugot = 0;
}

static void process_event(rec_state *rs, const kd_buf *e) {
    u32 code = e->debugid & ~3u, fn = e->debugid & 3u;
    if (rs->raw) {
        int i;
        for (i = 0; i < rs->nraw && rs->raw_ids[i] != e->debugid; i++) {}
        if (i == rs->nraw && rs->nraw < 256) rs->raw_ids[rs->nraw++] = e->debugid;
        if (i < 256) rs->raw_counts[i]++;
    }
    if ((code >> 24) != 0x25) return;
    thread_state *t = thread_get(rs, e->arg5);
    const u64 args[4] = { e->arg1, e->arg2, e->arg3, e->arg4 };

    switch (code) {
    case PERF_GEN_EVENT:
        if (fn == DBG_FUNC_START) {
            // Timer samples carry our action id; the deferred user-stack sample
            // taken later on the way back to user space carries action 0.
            t->in_timer = (e->arg2 == REC_ACTION);
            t->cur_kernel = false;
            if (t->in_timer) t->pending++;
        } else if (fn == DBG_FUNC_END) {
            if (t->in_timer && t->cur_kernel && t->pending) t->pending_kernel++;
            t->in_timer = false;
        }
        break;
    case PERF_TI_DATA:
        t->pid = (int)e->arg1;
        break;
    case PERF_CS_KHDR:
        t->kwant = (u32)(e->arg2 + e->arg4);
        t->kgot = 0;
        break;
    case PERF_CS_KDATA:
        // Unslid kernel addresses live at the top of the address space; a
        // kernel stack whose first frame isn't one means we interrupted user code.
        if (t->kgot == 0 && t->kwant && (e->arg1 >> 48) == 0xffff) t->cur_kernel = true;
        t->kgot += 4;
        break;
    case PERF_CS_UHDR:
        t->uwant = (u32)(e->arg2 + e->arg4);
        if (t->uwant > MAX_FRAMES) t->uwant = MAX_FRAMES;
        t->ugot = 0;
        if (t->uwant == 0) emit_user_stack(rs, t);
        break;
    case PERF_CS_UDATA:
        for (int i = 0; i < 4 && t->ugot < t->uwant; i++) t->uframes[t->ugot++] = args[i];
        if (t->uwant && t->ugot == t->uwant) emit_user_stack(rs, t);
        break;
    }
}

// --- record: symbolication ------------------------------------------------------------
//
// The target is usually gone by the time we symbolicate, so we snapshot its
// executable mappings while it runs. System libraries live in the dyld shared
// cache, which is mapped at the same address in every process, so we resolve
// those against our own copy (dyld_shared_cache_iterate_text) instead.

struct dyld_shared_cache_dylib_text_info {
    u64         version;
    u64         loadAddressUnslid;
    u64         textSegmentSize;
    uuid_t      dylibUuid;
    const char *path;
    u64         textSegmentOffset;
};
extern int  dyld_shared_cache_iterate_text(const uuid_t cache_uuid,
                                           void (^cb)(const struct dyld_shared_cache_dylib_text_info *));
extern bool _dyld_get_shared_cache_uuid(uuid_t uuid);

typedef struct {
    u64   start, end, load;
    u64   text_off;   // file offset of the lowest mapping (fat binaries start mid-file)
    char *path;
} image;

static image *g_cache_images, *g_proc_images;
static usize  g_ncache, g_nproc;

static int image_cmp(const void *a, const void *b) {
    const image *x = a, *y = b;
    return x->start < y->start ? -1 : x->start > y->start;
}

static void load_shared_cache_images(void) {
    uuid_t uuid;
    if (!_dyld_get_shared_cache_uuid(uuid)) return;
    // Slide = where a known cache dylib really is minus its unslid address.
    Dl_info di;
    if (!dladdr((void *)qsort, &di)) return;
    __block u64 unslid = 0;
    __block usize n = 0, cap = 4096;
    g_cache_images = xcalloc(cap, sizeof(image));
    dyld_shared_cache_iterate_text(uuid, ^(const struct dyld_shared_cache_dylib_text_info *info) {
        if (!strcmp(info->path, di.dli_fname)) unslid = info->loadAddressUnslid;
        if (n == cap) { cap *= 2; g_cache_images = xrealloc(g_cache_images, cap * sizeof(image)); }
        g_cache_images[n].start = info->loadAddressUnslid;
        g_cache_images[n].end   = info->loadAddressUnslid + info->textSegmentSize;
        g_cache_images[n].path  = strdup(info->path);
        n++;
    });
    u64 slide = unslid ? (u64)di.dli_fbase - unslid : 0;
    for (usize i = 0; i < n; i++) {
        g_cache_images[i].start += slide;
        g_cache_images[i].end   += slide;
        g_cache_images[i].load   = g_cache_images[i].start;
    }
    qsort(g_cache_images, n, sizeof(image), image_cmp);
    g_ncache = n;
}

// Walk the target's VM regions and remember every file-backed executable mapping.
static void snapshot_images(pid_t pid) {
    struct proc_regionwithpathinfo rp;
    u64 addr = 0;
    while (proc_pidinfo(pid, PROC_PIDREGIONPATHINFO, addr, &rp, sizeof(rp)) == (int)sizeof(rp)) {
        u64 start = rp.prp_prinfo.pri_address, end = start + rp.prp_prinfo.pri_size;
        const char *path = rp.prp_vip.vip_path;
        if (end <= addr) break;
        addr = end;
        if (!(rp.prp_prinfo.pri_protection & VM_PROT_EXECUTE) || !path[0] || strstr(path, "dyld_shared_cache"))
            continue;
        // The mapping with the lowest file offset is __TEXT, which starts
        // with the Mach-O header: that's the load address atos wants.
        u64 off = rp.prp_prinfo.pri_offset;
        usize i;
        for (i = 0; i < g_nproc && strcmp(g_proc_images[i].path, path); i++) {}
        if (i == g_nproc) {
            g_proc_images = xrealloc(g_proc_images, (g_nproc + 1) * sizeof(image));
            g_proc_images[i] = (image){ start, end, start, off, strdup(path) };
            g_nproc++;
        } else {
            image *im = &g_proc_images[i];
            if (start < im->start) im->start = start;
            if (end > im->end) im->end = end;
            if (off < im->text_off) { im->text_off = off; im->load = start; }
        }
    }
}

static image *find_image(u64 addr) {
    for (usize i = 0; i < g_nproc; i++)
        if (addr >= g_proc_images[i].start && addr < g_proc_images[i].end) return &g_proc_images[i];
    usize lo = 0, hi = g_ncache;
    while (lo < hi) {
        usize mid = (lo + hi) / 2;
        if (g_cache_images[mid].end <= addr) lo = mid + 1;
        else hi = mid;
    }
    if (lo < g_ncache && addr >= g_cache_images[lo].start) return &g_cache_images[lo];
    return NULL;
}

// Run a command and return its stdout.
static char *run_capture(char **argv) {
    int fds[2];
    if (pipe(fds)) return NULL;
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, fds[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&fa, fds[0]);
    pid_t pid;
    int r = posix_spawnp(&pid, argv[0], &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    close(fds[1]);
    if (r) { close(fds[0]); return NULL; }
    usize len = 0, cap = 1 << 16;
    char *out = xcalloc(cap, 1);
    ssize_t got;
    while ((got = read(fds[0], out + len, cap - len - 1)) > 0) {
        len += (usize)got;
        if (cap - len < 4096) { cap *= 2; out = xrealloc(out, cap); }
    }
    out[len] = 0;
    close(fds[0]);
    waitpid(pid, NULL, 0);
    return out;
}

typedef struct {
    u64    addr;
    image *img;
    char  *func;
    usize  stat;   // index into the report's per-function table
} sym_entry;

static int sym_cmp(const void *a, const void *b) {
    const sym_entry *x = a, *y = b;
    if (x->img != y->img) return x->img < y->img ? -1 : 1;
    return x->addr < y->addr ? -1 : x->addr > y->addr;
}

static int sym_addr_cmp(const void *a, const void *b) {
    const sym_entry *x = a, *y = b;
    return x->addr < y->addr ? -1 : x->addr > y->addr;
}

static const char *basename_of(const char *path) {
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}

// "foo (in libfoo.dylib) + 12"  /  "main (in a.out) (main.c:9)"  ->  "foo" / "main"
static char *clean_atos_line(const char *line, usize len) {
    const char *in = strstr(line, " (in ");
    if (in && in < line + len) len = (usize)(in - line);
    return strndup(line, len);
}

// Resolve every unique address with one `atos` call per image (chunked).
static void symbolicate(sym_entry *syms, usize n) {
    qsort(syms, n, sizeof(sym_entry), sym_cmp);
    for (usize i = 0; i < n;) {
        usize j = i;
        while (j < n && syms[j].img == syms[i].img && j - i < 4000) j++;
        image *img = syms[i].img;
        char *out = NULL;
        if (img) {
            char **argv = xcalloc(j - i + 8, sizeof(char *));
            char load[32];
            snprintf(load, sizeof(load), "0x%llx", (unsigned long long)img->load);
            int a = 0;
            argv[a++] = "atos"; argv[a++] = "-o"; argv[a++] = img->path; argv[a++] = "-l"; argv[a++] = load;
            for (usize k = i; k < j; k++) asprintf(&argv[a++], "0x%llx", (unsigned long long)syms[k].addr);
            out = run_capture(argv);
            for (int k = 5; k < a; k++) free(argv[k]);
            free(argv);
        }
        char *line = out;
        for (usize k = i; k < j; k++) {
            char *nl = line ? strchr(line, '\n') : NULL;
            if (line && nl && strncmp(line, "0x", 2)) syms[k].func = clean_atos_line(line, (usize)(nl - line));
            else if (img) asprintf(&syms[k].func, "%s+0x%llx", basename_of(img->path),
                                   (unsigned long long)(syms[k].addr - img->load));
            else asprintf(&syms[k].func, "0x%llx", (unsigned long long)syms[k].addr);
            line = nl ? nl + 1 : NULL;
        }
        free(out);
        i = j;
    }
    qsort(syms, n, sizeof(sym_entry), sym_addr_cmp);
}

static sym_entry *lookup_sym(sym_entry *syms, usize n, u64 addr) {
    sym_entry key = { .addr = addr };
    return bsearch(&key, syms, n, sizeof(sym_entry), sym_addr_cmp);
}

// Return addresses point after the call; step back one byte so they land in
// the calling function (and on the call's line).
static u64 frame_pc(const stack_entry *s, u32 i) { return i == 0 ? s->frames[i] : s->frames[i] - 1; }

// --- record: report -------------------------------------------------------------------

typedef struct {
    const char *func, *module;
    u64 self, total;
    u32 last_stack;   // dedupe recursion when computing "children"
} sym_stat;

static const char *sym_module(const sym_entry *s) { return s->img ? basename_of(s->img->path) : "?"; }

static int sym_name_cmp(const void *a, const void *b) {
    const sym_entry *x = *(sym_entry *const *)a, *y = *(sym_entry *const *)b;
    int r = strcmp(x->func, y->func);
    return r ? r : strcmp(sym_module(x), sym_module(y));
}

// Give every distinct (function, module) one sym_stat slot; slot 0 is [kernel].
static sym_stat *intern_functions(sym_entry *syms, usize n, usize *nstats) {
    sym_entry **order = xcalloc(n ? n : 1, sizeof(sym_entry *));
    for (usize i = 0; i < n; i++) order[i] = &syms[i];
    qsort(order, n, sizeof(sym_entry *), sym_name_cmp);
    sym_stat *stats = xcalloc(n + 1, sizeof(sym_stat));
    stats[0] = (sym_stat){ "[kernel]", "kernel", 0, 0, 0 };
    usize k = 1;
    for (usize i = 0; i < n; i++) {
        if (i == 0 || sym_name_cmp(&order[i - 1], &order[i]))
            stats[k++] = (sym_stat){ order[i]->func, sym_module(order[i]), 0, 0, 0 };
        order[i]->stat = k - 1;
    }
    free(order);
    *nstats = k;
    return stats;
}

static int symstat_cmp(const void *a, const void *b) {
    const sym_stat *x = a, *y = b;
    if (x->self != y->self) return x->self < y->self ? 1 : -1;
    return x->total < y->total ? 1 : (x->total > y->total ? -1 : 0);
}

static int u64_desc_thread_cmp(const void *a, const void *b) {
    const thread_state *x = a, *y = b;
    return x->samples < y->samples ? 1 : (x->samples > y->samples ? -1 : 0);
}

static void report(rec_state *rs, const char *out_path, int top, int hz) {
    // 1. Unique addresses -> symbols.
    usize nsyms = 0, cap = 1024;
    sym_entry *syms = xcalloc(cap, sizeof(sym_entry));
    for (usize s = 0; s < rs->cap; s++) {
        stack_entry *st = &rs->stacks[s];
        if (!st->frames) continue;
        for (u32 i = 0; i < st->n; i++) {
            if (nsyms == cap) { cap *= 2; syms = xrealloc(syms, cap * sizeof(sym_entry)); }
            syms[nsyms++].addr = frame_pc(st, i);
        }
    }
    qsort(syms, nsyms, sizeof(sym_entry), sym_addr_cmp);
    usize u = 0;
    for (usize i = 0; i < nsyms; i++)
        if (!u || syms[i].addr != syms[u - 1].addr) syms[u++] = syms[i];
    nsyms = u;
    for (usize i = 0; i < nsyms; i++) syms[i].img = find_image(syms[i].addr);
    symbolicate(syms, nsyms);

    // 2. Folded stacks (root;...;leaf count) + per-function self/children.
    FILE *f = fopen(out_path, "w");
    if (!f) die("cannot write %s: %s", out_path, strerror(errno));
    usize nstats = 0;
    sym_stat *stats = intern_functions(syms, nsyms, &nstats);
    u32 stack_no = 0;
    for (usize s = 0; s < rs->cap; s++) {
        stack_entry *st = &rs->stacks[s];
        if (!st->frames) continue;
        stack_no++;
        for (int i = (int)st->n - 1; i >= 0; i--)
            fprintf(f, "%s%s", i == (int)st->n - 1 ? "" : ";", lookup_sym(syms, nsyms, frame_pc(st, (u32)i))->func);
        fprintf(f, "%s %llu\n", st->kernel ? ";[kernel]" : "", (unsigned long long)st->count);

        for (int i = st->kernel ? -1 : 0; i < (int)st->n; i++) {
            usize k = i < 0 ? 0 : lookup_sym(syms, nsyms, frame_pc(st, (u32)i))->stat;
            bool leaf = st->kernel ? i == -1 : i == 0;
            if (leaf) stats[k].self += st->count;
            if (stats[k].last_stack != stack_no) {
                stats[k].total += st->count;
                stats[k].last_stack = stack_no;
            }
        }
    }
    fclose(f);

    // 3. Print.
    qsort(stats, nstats, sizeof(sym_stat), symstat_cmp);
    qsort(rs->threads, rs->nthreads, sizeof(thread_state), u64_desc_thread_cmp);
    usize active = 0;
    for (usize i = 0; i < rs->nthreads; i++) active += rs->threads[i].samples > 0;
    double tot = rs->total ? (double)rs->total : 1;

    printf("# %s samples @ %d Hz (~%.2f s on-CPU), %zu threads, %s lost\n",
           commas(rs->total), hz, rs->total / (double)hz, active, commas(rs->lost));
    printf("#\n#     Self  Children  Symbol%-36s Module\n", "");
    for (usize i = 0; i < nstats && (int)i < top; i++)
        printf("  %7.2f%%  %7.2f%%  %-42.42s %s\n", 100 * stats[i].self / tot, 100 * stats[i].total / tot,
               stats[i].func, stats[i].module);
    if (active > 1) {
        printf("#\n# per thread:\n");
        for (usize i = 0; i < rs->nthreads && rs->threads[i].samples; i++)
            printf("  tid %-10llu %7.2f%%\n", (unsigned long long)rs->threads[i].tid,
                   100 * rs->threads[i].samples / tot);
    }
    if (rs->raw) {
        printf("#\n# raw kdebug ids seen:\n");
        for (int i = 0; i < rs->nraw; i++)
            printf("  0x%08x  %s\n", rs->raw_ids[i], commas(rs->raw_counts[i]));
    }
    printf("#\n# folded stacks: %s (%s unique) -> https://speedscope.app or flamegraph.pl\n",
           out_path, commas(rs->nstacks));
}

// --- record: driver --------------------------------------------------------------------

static void record_usage(void) {
    fprintf(stderr,
        "usage: sudo simple_perf record [options] [--] <command> [args...]\n"
        "       sudo simple_perf record [options] -p <pid>\n\n"
        "  -F hz      sampling frequency (default 1000)\n"
        "  -k         also sample kernel stacks (shown as a [kernel] leaf)\n"
        "  -o file    folded-stack output (default perf.folded)\n"
        "  -p pid     profile a running process (Ctrl-C to stop)\n"
        "  -t sec     stop after sec seconds\n"
        "  -n N       rows in the report (default 30)\n"
        "  --raw      also dump a histogram of raw kdebug ids (for debugging)\n");
    exit(1);
}

#define KD_NBUFS     (1 << 20)  // kernel trace buffer, in events
#define KD_READ_MAX  (1 << 18)

static int cmd_record(int argc, char **argv) {
    static rec_state rs;
    int hz = 1000, top = 30, c;
    bool kernel = false;
    const char *out_path = "perf.folded";
    pid_t pid = 0;
    u64 duration_ns = 0;
    static const struct option longopts[] = { { "raw", no_argument, NULL, 'R' }, { 0 } };
    optind = 1; optreset = 1;
    while ((c = getopt_long(argc, argv, "+F:ko:p:t:n:h", longopts, NULL)) != -1) {
        switch (c) {
        case 'F': hz = atoi(optarg); break;
        case 'k': kernel = true; break;
        case 'o': out_path = optarg; break;
        case 'p': pid = atoi(optarg); break;
        case 't': duration_ns = (u64)(atof(optarg) * 1e9); break;
        case 'n': top = atoi(optarg); break;
        case 'R': rs.raw = true; break;
        default: record_usage();
        }
    }
    char **cmd = optind < argc ? &argv[optind] : NULL;
    if (!cmd == !pid || hz <= 0) record_usage();
    if (geteuid() != 0) die("record needs root: run with sudo");
    load_frameworks();
    load_shared_cache_images();
    catch_sigint();

    // Start the command suspended so we can aim kperf at its pid before it runs.
    if (cmd) pid = g_child = spawn_cmd(cmd, true);
    snapshot_images(pid);

    kdebug_start(KD_NBUFS);
    g_kperf_active = true;
    u32 samplers = SAMPLER_TH_INFO | SAMPLER_USTACK | (kernel ? SAMPLER_KSTACK : 0);
    if (kperf_reset() ||
        kperf_action_count_set(REC_ACTION) ||
        kperf_action_samplers_set(REC_ACTION, samplers) ||
        kperf_action_filter_set_by_pid(REC_ACTION, pid) ||
        kperf_timer_count_set(1) ||
        kperf_timer_period_set(0, kperf_ns_to_ticks(1000000000ull / (u64)hz)) ||
        kperf_timer_action_set(0, REC_ACTION) ||
        kperf_sample_set(1))
        die("kperf setup failed: %s (is Instruments/ktrace using kperf?)", strerror(errno));

    if (cmd) kill(pid, SIGCONT);
    kd_buf *buf = xcalloc(KD_READ_MAX, sizeof(kd_buf));
    u64 t0 = now_ns(), next_snap = t0 + 50 * 1000 * 1000;
    for (;;) {
        bool done = cmd ? child_exited(pid, false) : (g_stop || kill(pid, 0) != 0);
        if (duration_ns && now_ns() - t0 >= duration_ns) done = true;
        if (done) break;
        usleep(10 * 1000);
        usize n = kdebug_read(buf, KD_READ_MAX);
        for (usize i = 0; i < n; i++) process_event(&rs, &buf[i]);
        if (now_ns() >= next_snap) {  // pick up dlopen'd images while the target is alive
            snapshot_images(pid);
            next_snap = now_ns() + 500 * 1000 * 1000;
        }
    }
    kperf_sample_set(0);
    usize n;
    while ((n = kdebug_read(buf, KD_READ_MAX)) > 0)
        for (usize i = 0; i < n; i++) process_event(&rs, &buf[i]);
    if (kdebug_dropped()) fprintf(stderr, "simple_perf: trace buffer filled up; some samples were dropped\n");
    cleanup();  // stops kperf/kdebug; also kills the command if we stopped early (-t)
    free(buf);

    for (usize i = 0; i < rs.nthreads; i++) rs.lost += rs.threads[i].pending;
    if (!rs.total) {
        fprintf(stderr, "simple_perf: no samples (did the target run on-CPU?)%s\n",
                rs.raw ? "" : " -- try --raw");
        if (!rs.raw) return 1;
    }
    report(&rs, out_path, top, hz);
    return 0;
}

// --- main -------------------------------------------------------------------------

static void usage(void) {
    fprintf(stderr,
        "usage: simple_perf <command> [args]\n\n"
        "  list [pattern]               list PMU events for this CPU\n"
        "  stat [opts] [--] cmd [args]  count events (plain stat needs no root)\n"
        "  record [opts] [--] cmd       sample call stacks, write folded stacks (root)\n"
        "  bench [-e ev,...] [name...]  built-in microbenchmarks with exact counters (root)\n"
        "  info                         CPU / PMU details\n\n"
        "Run a command with -h for its options.\n");
    exit(1);
}

int main(int argc, char **argv) {
    if (argc < 2) usage();
    atexit(cleanup);
    const char *sub = argv[1];
    argc--; argv++;
    if (!strcmp(sub, "list"))   return cmd_list(argc, argv);
    if (!strcmp(sub, "stat"))   return cmd_stat(argc, argv);
    if (!strcmp(sub, "record")) return cmd_record(argc, argv);
    if (!strcmp(sub, "bench"))  return cmd_bench(argc, argv);
    if (!strcmp(sub, "info"))   return cmd_info();
    usage();
}
