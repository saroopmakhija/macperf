`simple_perf.c` is a small `perf`-like tool for Apple Silicon Macs, built on Apple's private
`kperf`/`kperfdata` frameworks (no public headers; loaded with `dlopen`).
I started it because Instruments wasn't working on my M4 Mac, and I use it to learn how
Apple's performance-counter internals work. `re/NOTES.md` covers how the APIs were
reverse engineered.

```
clang -O2 -o simple_perf simple_perf.c

./simple_perf list [pattern]                  # PMU events + perf-style aliases
./simple_perf info                            # CPU / PMU details
./simple_perf stat -r 5 -- ./prog             # cycles, IPC, P/E split, energy (no root)
sudo ./simple_perf stat -d -- ./prog          # + branches/misses/stalls (system-wide)
sudo ./simple_perf stat -e INST_INT_LD,INST_INT_ST,branch-misses -I 500 -a
sudo ./simple_perf bench                      # microbenchmarks, exact thread counters
sudo ./simple_perf record -F 2000 -- ./prog   # sampling profiler -> perf.folded
```

Notes:
- `stat` with no options reads the kernel's own per-process accounting. It's exact and
  covers every thread.
- `kpc` can't count configurable events for a single process, so `-e`/`-d` count on all
  CPUs. If more events are asked for than there are counters, they're multiplexed and
  scaled, like perf does.
- `record` writes folded stacks. Open them with https://speedscope.app or `flamegraph.pl`.
