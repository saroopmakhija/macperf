# Reverse-engineering notes: kperf / kperfdata (macOS 26.3, Apple M4)

Everything here was checked on this machine (`cpu_100000c_2_6f5129ac`, kpep db `as4`).
The method was the same each time:

- **Symbol lists:** `dyld_info -exports <framework>` lists each library's exports. The
  libraries only exist inside the dyld shared cache. The output is in `*.exports.txt`.
- **Disassembly:** `lldb` on any binary, then `expr (void*)dlopen(...)` and `dis -n <func>`.
  Most `kpc_*` / `kperf_*` functions are thin wrappers around a `sysctlbyname` call, so
  the sysctl string and the argument packing give away each function's signature.
- **Experiments:** the `kpep_*` functions do pure computation and work without root. So
  I fed them inputs and diffed the outputs.

## kperf.framework (120 exports): counters and sampling

| Function | Signature | Wraps / notes |
|---|---|---|
| `kpc_get_counter_count` | `u32 (u32 classes)` | `kpc.counter_count`. M4: 2 fixed + 8 configurable |
| `kpc_get_config_count` | `u32 (u32 classes)` | `kpc.config_count` (8) |
| `kpc_get_thread_counters` | `int (u32 tid, u32 n, u64 *buf)` | `kpc.thread_counters`. `tid` is passed as newp, but only the **current** thread can be read |
| `kpc_get_cpu_counters` | `int (bool all, u32 classes, int *curcpu, u64 *buf)` | `kpc.counters`. With all=1 you get `ncpu * counter_count` values, CPU-major. `*curcpu` = first word |
| `kpc_cpu_string` | `int (char *buf, usize len)` | `"cpu_%x_%x_%x"` from cputype / subtype / cpufamily. Names the `/usr/share/kpep/*.plist` file |
| `kpc_set_period` / `kpc_set_actionid` | `int (u32 classes, u64/u32 *vals)` | `kpc.period` / `kpc.actionid`: PMI sampling (counter overflow, then run a kperf action) |
| `kperf_action_filter_set_by_pid` | `int (u32 action, int pid)` | `kperf.action.filter_by_pid`, packs `{action, pid}` |
| `kperf_action_samplers_set` | `int (u32 action, u32 samplers)` | `kperf.action.samplers` |
| `kperf_timer_period_set` | `int (u32 timer, u64 ticks)` | `kperf.timer.period`, packs `{timer, ticks}` |
| `kperf_timer_action_set` | `int (u32 timer, u32 action)` | `kperf.timer.action` |
| `kperf_sample_set` | `int (u32 on)` | `kperf.sampling` |
| `kperf_ns_to_ticks` | `u64 (u64 ns)` | uses `mach_timebase_info` |
| `kperf_logging_start/stop/set_size` | | kperf's own kdebug driver (see below). Default buffer = 1,000,000 events |
| `kperf_typefilter_enable_subclass` | `void (u8 *bitmap, u8 class, u8 sub)` | sets bit `(class<<8)\|sub` in an 8 KiB bitmap |

Also exported but not used yet: `kperf_kdebug_*` (sample when a given kdebug event fires),
`kperf_lazy_wait_*` / `kperf_lazy_cpu_*` (sample threads that block or run too long),
`kperf_timer_pet_set` (profile-every-thread mode), `kperf_kdbg_cswitch_set`, and
`kperf_bless_*` (claim kperf exclusively).

### How kperf drives kdebug (from `kperf_logging_start`)

These are the MIB constants read out of kperf's data section. Every MIB starts with
`CTL_KERN(1), KERN_KDEBUG(24)`:

```
trace_clear     {1,24,7}            KERN_KDREMOVE
trace_bufinit   {1,24,4,nbufs}      KERN_KDSETBUF, then {1,24,6} KERN_KDSETUP
trace_set_nowrap{1,24,1,2}          KERN_KDEFLAGS, KDBG_NOWRAP
trace_perf_filter {1,24,8} + kd_regtype{KDBG_CLASSTYPE=0x10000, 0x25, 0x26}   only DBG_PERF events
trace_set_typefilter {1,24,22}      8192-byte bitmap passed as *oldp*
trace_enable    {1,24,3,on}         KERN_KDENABLE
trace_block     {1,24,23}           KERN_KDBUFWAIT, timeout in ms passed through *oldlenp
                {1,24,10}           KERN_KDREADTR: bytes in, kd_buf count out
```

## kperfdata.framework (81 exports): event database

- `kpep_db_events(db, kpep_event **buf, usize buf_bytes)`: `buf_bytes` must be at least
  `count*8`. Otherwise it returns 4 ("buffer too small"). The result is sorted by name.
- The `kpep_event` layout was checked against the plist. Offsets: `name@0x00`,
  `description@0x08`, `errata@0x10`, `alias@0x18`, `fallback@0x20`, `counters_mask@0x28`
  (u32), `number@0x2c` (u32), `is_fixed@0x30` (u8).
- **`kpep_config_add_event` flag:** the flag is stored per counter slot. Only bit 0 matters:
  it ORs `0x20000` (EL0, user-only) into the config word. Flags 2 to 7 produce identical
  registers. Kernel-only means writing `0x40000` (EL1) by hand.
- **Conflicts:** the return value 12 means "conflicting events". In that case `*err` is a
  **bitmask of the counter slots** that clashed. This is enough to build multiplexing:
  first-fit packing into groups, rotated in turn.
- `kpep_strerror(0..15)`: none, invalid argument, out of memory, I/O, buffer too small,
  current system unknown, db path invalid, db not found, db arch unsupported, db version
  unsupported, db corrupt, event not found, conflicting events, all counters must be
  forced, event unavailable, (errno).

### The M4 PMU (`/usr/share/kpep/as4.plist`)

- 103 events. 2 fixed counters: cycles is slot 0 and instructions is slot 1.
  8 configurable counters in slots 2 to 9 (`config_counters = 0x3fc`).
- Constraints:
  - 25 events only fit slots 2 to 7 (mask `0xfc`). These are most retired-instruction and
    branch events.
  - 5 events only fit **slot 7** (mask `0x80`), e.g. `INST_INT_LD`, `INST_INT_ST`, so at
    most one of them can be counted at a time.
  - The rest go anywhere.
- `hw.cpufamily` 0x6f5129ac maps to `cpu_100000c_2_6f5129ac.plist`, which links to `as4.plist`.

## No root needed: per-process counters from the kernel

`proc_pid_rusage(pid, RUSAGE_INFO_V6)` exposes exact, all-thread `ri_cycles`,
`ri_instructions`, `ri_pcycles`, `ri_pinstructions` (P-cores only), `ri_energy_nj` and
`ri_penergy_nj`. It still works on a zombie child (`waitid(..., WNOWAIT)`), so the
counts include the whole lifetime. The `ri_*_time` fields are in mach ticks, not ns.

## Dead ends

- **Configurable events for another process.** kpc only reads the calling thread's
  counters, and per-thread counts are thrown away when a thread exits. So per-process
  configurable counts need either sampling (kperf `PMC_THREAD` sampler) or system-wide
  counting. `stat -e` does system-wide.

## kperf sample format (from XNU's open-source `osfmk/kperf`, not yet checked live)

| debugid | meaning |
|---|---|
| `0x25000001` / `…02` | sample start / end. arg1 = samplers, arg2 = action id (0 = deferred AST sample) |
| `0x25010004` | thread info: pid, tid, dispatch-queue address, run mode |
| `0x25020014` / `0x25020018` | kernel / user stack header: flags, nframes, async index, async nframes |
| `0x2502000c` / `0x25020010` | 4 kernel / user frames per event |

User stacks taken from a timer interrupt are **deferred**. They are logged later, on the
thread's way back to user space, as a separate sample with action 0. The last user frame
is a "fixup" word (the saved LR) rather than a real frame. `record --raw` prints a
histogram of the debugids it actually saw, to check these assumptions.
