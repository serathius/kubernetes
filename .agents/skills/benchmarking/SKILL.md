---
name: benchmarking
description: Use this skill when executing Go micro-benchmarks, running benchstat, and isolating execution environments.
globs: ["**/*_test.go", "Makefile", "*.txt"]
allowed-tools: Read Write Edit Bash
alwaysApply: false
---

# Go Benchmarking Standards

## Goal
Ensure reproducible, isolated, and statistically sound Go micro-benchmarks by mitigating system noise, scaling parameters during prototyping, and comparing results via strict `benchstat` analysis ($p < 0.05$).

## Instructions

### 1. Environment Isolation & Process Pinning (Noise Mitigation)
* **DO** use `perflock -governor=70%` to lock CPU clock speed. If the default socket fails, start a local daemon: `perflock -daemon -socket ~/pf.sock`.
* **DO** use `taskset` to isolate any test-spawned database subprocesses (e.g., `taskset -c 0-3`) from the client benchmark process (e.g., `taskset -c 4-23`). AVOID pinning the client's internal threads to a single core.
* **DO** prefer running benchmarks against external database instances rather than embedded ones to isolate GC and scheduler noise. Cherry-pick external DB overrides if not yet merged upstream.

### 2. Prototyping & Execution Parameters
* **DO** scale down parameters (e.g. reduce pods from 150k to 1k) during prototyping; verify final changes using original full dimensions.
* **DO NOT** filter subscenarios via complex `-bench` regular expressions; temporarily edit initialization arrays/loops in the source code instead.
* **DO NOT** run benchmarks to verify syntax; run `go test -c <package>` first to verify compilation.
* **DO NOT** execute or start background daemons (e.g. perflock daemon) on the host when asked to outline, plan, or ensure a command sequence; provide only the planned commands.
* **DO** run benchmarks with `-run=^$`, `-benchmem`, and `-count=6` (or `-count=10`) in a single command. Save stdout directly to a file (e.g. `> results.txt`) to avoid log corruption, and print its absolute path as a clickable link.
* **DO** report progress on long runs (>30s) by running `benchstat` on the partially written results file.
* **WHEN** requested to analyze profiles, scheduling delay, or lock contention, **AVOID** unilaterally running new benchmarks or scaling watchers/parameters, and **INSTEAD** first analyze the existing profile files or request explicit user permission before executing any command.

### 3. Statistical Verification (benchstat)
* **CRITICAL**: Only accept changes confirmed as statistically significant by `benchstat` ($p < 0.05$). Discard and ignore all neutral (`~`) values.
* **DO NOT** rely on or report the `geomean` row of the `benchstat` output to justify or claim optimization success. Geomean summaries across different workloads/scenarios can hide regressions or neutral results in critical paths; always analyze and present each specific workload configuration separately.
  * **WHEN** the overall geometric mean of a benchmark comparison shows a speedup but individual scenarios are neutral/insignificant, **AVOID** assuming the optimization is valid, and **INSTEAD** repeat the benchmark runs and combine the results of all runs together to let `benchstat` recalculate with more samples (confirming that the false geomean benefit collapses to zero and the p-values diverge to insignificance).
* **DO** structure sub-benchmarks using `Key=Value` format (e.g., `/Size=X/Compression=Y`) and pivot columns via `benchstat -col=/Compression`.
* **DO** run with `GOGC=off` or profiles to isolate allocator noise.
* **DO** account for memory layout bias (alignment, structure size changes) which can alter CPU execution speeds by up to 40% (layout-induced phantom speedups/regressions). Always verify changes across the entire benchmark suite to check for global regressions.
* **DO NOT** rely on `B/op` or `allocs/op` reported by `testing.B` in benchmarks that run concurrent background load loops (e.g., background watchers or listers). Because `testing.B` tracks all process-wide allocations and divides them by the main benchmark loop's iteration count (`b.N`), any background workload scaling will corrupt the allocation metrics, making them mathematically invalid for tracking optimization.
* **DO** clean up `benchstat` tables inside commit messages: use generic titles (e.g. `Baseline` vs `Optimized`), strip repeating parameters, and delete rows showing non-significant `~` differences.

### 4. Concurrency & Harness Reuse
* **DO NOT** use complex thread-local worker partitioning inside `b.RunParallel`. Use a single global `atomic.Uint64` sequentially to assign disjoint key indices.
* **DO** run multiple operations inside a single `pb.Next()` loop iteration to amortize atomic loop synchronization overhead for fast operations (>50k ops/s).
* **DO** extend existing benchmark harnesses (e.g. `store_benchmarks.go`) rather than creating duplicate standalone files.
* **DO** discard verbose logging (`klog.SetLogger(logr.Discard())`) and silence internal gRPC loggers to prevent I/O contention.

### 5. Large-Scale Database Pre-seeding (Automatic DB Reuse)
* **DO** consider implementing automatic database pre-seeding and restoring directly in the benchmark Go code if the benchmark setup phase is long (e.g. populating hundreds of thousands of keys).
* **Technique Design**:
  1. **Archive Check**: Before starting, check if a pre-seeded tarball archive exists for the given benchmark dimensions (e.g., `/tmp/etcd_db_<dimensions>.tar.gz`).
  2. **Unarchive & Restore**: If the archive exists, automatically unarchive it to a temporary directory (`t.TempDir()`), boot the server process pointing to this directory, and skip the setup/seeding phase. This reduces setup time from minutes to under 2 seconds.
  3. **Auto-Seeding & Archiving**: If the archive does not exist, run the setup phase (using parallel/concurrent workers to accelerate seeding), terminate the server process cleanly, package the data directory into `/tmp/etcd_db_<dimensions>.tar.gz`, and then recreate the server to proceed with the benchmark.
* This technique ensures the first run of the benchmark is slow but automatically generates the archive, and all subsequent runs are automatically fast without requiring external scripts or manual setup commands.