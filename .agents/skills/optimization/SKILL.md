---
name: optimization
description: Use this skill when evaluating Go performance optimizations, analyzing profiles, or refactoring concurrent pipelines.
globs: ["**/*.go", "**/*.md"]
allowed-tools: Read Write Edit Bash
alwaysApply: false
---

# Goal
Ensure performance optimizations are mathematically verified, preventing wasted effort on layout-induced phantom regressions, memory-reduction lock tradeoffs, or concurrent pipeline profiling blindspots.

## Instructions

### 1. Evidence-Based Optimization & Layout Bias
* **DO** refer to the [benchmarking](../benchmarking/SKILL.md) skill for the strict rules on accurate performance analysis, statistical verification (`benchstat` $p < 0.05$), memory layout bias mitigation, and allocation profiling standards.
* **DO NOT** compile or execute benchmarks when asked to plan, analyze, or verify an optimization tradeoff conceptually; outline the verification plan first.
* **DO** account for memory layout bias (alignment, size changes) which can alter benchmark speeds by up to 40%. Verify changes across the entire suite to check for global regressions.
* **DO NOT** assume eliminating heap allocations is always a net positive; verify that memory pooling (e.g. `sync.Pool`) does not introduce mutex contention or CPU cache invalidations under high concurrency.
*   **DO** recognize that performance optimization is an iterative process of identifying and resolving dependent bottlenecks. Sometimes the benefit of an optimization will not show up until you resolve a completely different, upstream or downstream bottleneck (e.g., concurrent decoding shows no benefit on indexed workloads because the index-filtering bottleneck must be solved first).
*   **DO** systematically build on active optimization paths, but maintain a ledger of rejected or neutral hypotheses to revisit later once other bottlenecks are removed, as the dependency landscape will have shifted.
*   **DO** recognize that maintaining an investigation journal (ledger of exploration) is critical for large-scale optimizations to prevent losing valuable context, track branching hypotheses, and avoid prematurely discarding ideas that are blocked by other active bottlenecks. Refer to the [investigation-journaling](../investigation-journaling/SKILL.md) skill to structure this journal.
*   **DO** if tasked with optimizing the API server watch cache, read the existing [Watch Cache Write Bottleneck Journal](references/watch_cache_write_bottleneck.md) and use the `investigation-journaling` standards to expand it.

### 2. Profiling Strategy: Traditional vs. Causal
* **Traditional Sampling (pprof)**: Use exclusively for synchronous, single-goroutine paths. Do NOT rely on it for concurrent, parallel, or pipelined systems where traditional profiles can be blind to server-side resource contention (e.g., database locks or page copying).
* **Causal Profiling (Delay Injection)**: Use as the default validation for concurrent Go pipelines/worker pools to confirm if a component is on the critical path. See [Causal Profiling Delay Injection Utilities](references/causal_profiling_delay_injection.md) for code implementation templates.
  * Inject a controlled `time.Sleep` delay into all *other* concurrent goroutines. If overall throughput drops significantly, the target component is NOT the bottleneck.
  * Model latency vs. concurrency using Little's Law:
    $$\text{Average Latency} = \frac{\text{Average Number of Active Goroutines}}{\text{Throughput Rate}}$$

### 3. Concurrency & Hashing Primitives
* **DO NOT** implement custom lock-free synchronization primitives, ring buffers, or concurrency layers; advise using standard channels or standard library sync primitives.
* **DO NOT** partition keys or design hashes by sequentially summing byte values. The Central Limit Theorem will clump keys into a Gaussian distribution, causing severe mutex/bucket contention.
* **DO** use uniform bitwise distribution (XOR `^` or FNV hashes) to ensure flat key address spread.

### 4. Cacher Benchmarking Script
* **DO** use the [run_cacher_benchmark.sh](scripts/run_cacher_benchmark.sh) helper script to run the watch cache write throughput benchmark under proper CPU isolation (`taskset`) and frequency lock (`perflock`) settings:
  ```bash
  BENCHMARK_OUTPUT_PATH=results.txt \
  BENCHMARK_COUNT=6 \
  ./.agents/skills/optimization/scripts/run_cacher_benchmark.sh
  ```
  Supported environment variables include:
  * `BENCHMARK_OUTPUT_PATH`: (Required) Path to write the raw benchmark results.
  * `BENCHMARK_COUNT`: Number of iterations to run (default: 6).
  * `WORKSPACE`: Path to the Kubernetes workspace root.

* **DO** use the [benchmark_history.sh](scripts/benchmark_history.sh) helper script to automate executing a sequence of commits and comparing each commit sequential performance delta with `benchstat`:
  ```bash
  BENCHMARK_BASELINE_HASH=dd21b067b88 \
  BENCHMARK_COMMITS="30acc84e8b7 7718fee98ff 643efb29b30 0ab7c386556 a62a5f1311e 4864c6a5f0b 05fa311f580 f3c5a1cd1c3 a353c936184" \
  BENCHMARK_COUNT=6 \
  ./.agents/skills/optimization/scripts/benchmark_history.sh
  ```
  Supported environment variables include:
  * `BENCHMARK_BASELINE_HASH`: (Required) Baseline commit hash.
  * `BENCHMARK_COMMITS`: (Required) Space-separated list of commit hashes to run.
  * `BENCHMARK_COUNT`: Number of iterations to run (default: 6).
  * `WORKSPACE`: Path to the Kubernetes workspace root.
