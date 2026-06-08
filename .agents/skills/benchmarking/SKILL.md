---
name: benchmarking
description: Triggers for Go performance testing, executing micro-benchmarks, running benchstat, tracking memory allocations, and mitigating thermal throttling.
globs: ["**/*_test.go", "Makefile", "*.txt"]
tools: [Read, Write, Edit, Bash]
alwaysApply: false
---

# Go Benchmarking Standards

## Goal
Ensure reproducible, isolated, and statistically sound Go micro-benchmarks by mitigating environmental noise, tracking memory allocations, and comparing results using strict `benchstat` statistical analysis.

## Instructions

### 1. Benchmarking Environment & Execution
* **DO** tune benchmark setup parameters or scale dimensions down (e.g., reduce dataset from `150,000` to `1,000` items) to speed up iterations during development, but **ALWAYS** validate the final changes using the full original benchmark parameters.
* **DO** isolate benchmarks from unit tests by using the regex flag `-run=^$`.
* **DO** run benchmarks multiple times (prefer `-count=6` up to `-count=10`) to establish a reliable distribution and lower the p-value.
* **DO** always include the `-benchmem` flag to track allocations (`allocs/op` and `B/op`), as memory pressure is a primary performance bottleneck in Go.
* **DO** use `perflock` (on Linux, e.g., with `-governor=70%` to lock the CPU frequency governor below max capacity) or `taskset` to ensure the CPU does not thermally throttle under heavy/concurrent load and to pin the process to specific cores.
* **DO** pipe benchmark output to `tee` to simultaneously view progress and persist results for comparison.
  ```bash
  perflock -governor=70% go test -run=^$ -bench=. -benchmem -count=6 | tee new_results.txt
  ```
* **DO** proactively provide periodic updates to the user for long-running benchmarks (>30s) by checking the background task log or running `benchstat` on the partial benchmark output file. `benchstat` safely ignores trailing incomplete lines and can summarize progress.

### 2. Statistical Verification with benchstat
* **CRITICAL**: ONLY trust values where `benchstat` reports a statistically significant difference (indicated by a `+` or `-` percentage and `p < 0.05`). If `benchstat` outputs a tilde `~` (e.g., `~ (p=0.589 n=6)`), the difference is statistically insignificant noise, no matter how large the nominal gap appears. NEVER report a `~` value or geomean as an improvement or regression.
* **DO** structure sub-benchmarks using exact `Key=Value` formatting (e.g., `BenchmarkFoo/Interning=True`) to enable automated data pivoting.
* **DO** use `benchstat` to analyze results. Do NOT rely on manual percentage calculations.
* **DO** use `benchstat -col` to pivot and compare the selected parameter dimension:
  ```bash
  benchstat -col=/Interning bench_results.txt
  ```
* **DO** mathematically verify changes:
  1. **Baseline Run:** Record performance on the unmodified code (e.g., `perflock go test -bench=. -count=6 > old_results.txt`).
  2. **Post-Fix Run:** Record performance on the modified code.
  3. **Evaluate:** Compare old vs. new using `benchstat`. **Reject your hypothesis** if the delta is statistically insignificant (high p-value).
  4. **Document:** Include the raw, complete comparative `benchstat` table for ALL measured metrics (e.g., `sec/op`, `writes/s`, `list-calls/s`, `list-objs/s`, `seconds-delay`) in both the change description and the git commit message. Do NOT omit any metric section.
* **CRITICAL**: Do not invent fixes for "regressions" until they are statistically verified. A regression is only real if `benchstat` confirms it with a `p < 0.05` difference. Ignore noisy `~` values and geomeans.
* **DO** benchmark the complete suite of scenarios (all traffic types, background loads, index configurations) to ensure full coverage matching the baseline.

### 3. Concurrent & Parallel Benchmarking (b.RunParallel)
* **DO NOT** use complex thread-local calculations, GOMAXPROCS multipliers, or worker ID indices to partition keys/work inside `b.RunParallel`.
* **DO** use a single global thread-safe atomic counter (`atomic.Uint64`) to assign unique, disjoint key indices sequentially across parallel goroutines (e.g. `i := int(globalIndex.Add(1)-1) % len(keys)`). This naturally prevents concurrent inter-worker writes to the same key and works identically regardless of GOMAXPROCS or spawned worker counts.
* **DO** be aware that `pb.Next()` has atomic synchronization overhead. If write operations are extremely fast (e.g. >50k ops/s), executing multiple operations per iteration can reduce `pb.Next()` contention and increase reported writes/s.

### 4. Benchmark Reuse, Logging
* **DO** always review the existing benchmark suite to see if new metrics (e.g. latency) or load conditions (e.g. exact RV list load) can be integrated into the existing framework (e.g. `store_benchmarks.go`) before implementing a duplicate, standalone benchmark. Reusing common setup, data preparation, and teardown logic maintains codebase dry-ness and cohesion.
* **DO** discard verbose logging (e.g. `klog.SetLogger(logr.Discard())`) at the start of the benchmark to avoid I/O bottlenecks that skew results (e.g., watch latency might show artificial spikes).

## Integration
* **Expert Persona:** Go Performance Engineer & Benchmark Architect.
* **MCP Tools:** None.

## Correct vs. Incorrect Patterns

### Sub-benchmark Naming
```go
// ❌ INCORRECT
b.Run("without_interning", func(b *testing.B) {
    // ...
})

//  CORRECT
b.Run("Interning=False", func(b *testing.B) {
    // ...
})
```
