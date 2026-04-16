`simple_perf.c` is a tiny playground for Apple Silicon performance counters (PMCs).
It uses `kperf` internal/private functions (there are no public headers) to configure and read counters.
The program runs a simple CPU workload and prints a few counter-derived stats (cycles, instructions, IPC).
Just using this to learn how apple internals work because apple instruments isnt working on my mac m4 and dont have time to debug 
Used a few medium blogs to basically reverse engineer the counter events


