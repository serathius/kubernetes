---
name: investigation-journaling
description: Use this skill when tasked with investigating, diagnosing, or resolving complex codebase issues (such as concurrency bugs, performance bottlenecks, or regression cascades). It defines a structured diagnostic ledger to track the branching tree of hypotheses and prevent loose ends.
globs: ["**/*.md"]
allowed-tools: Read Write Edit
alwaysApply: false
---

# Investigation Journaling Standards

## Goal
Establish a highly rigorous, methodical workflow for exploring complex diagnostic problem spaces. The investigation journal is a **ledger of exploration** designed to track the branching tree of hypotheses, prevent loose ends, and allow developers to systematically reconstruct evidence when contradictions or regressions arise.

## Instructions

### 1. The Methodical Exploration & Ledger Workflow (Generic Diagnostics)
* **DO** structure the investigation journal bimodeally: **Section 1** at the top containing the Executive Summary, current hypotesis, proposed verification actions, metrics, and red herrings; and **Section 2** below containing the historical ledger of diagnostics and detailed comparison tables.
* **DO** treat the investigation as a **branching tree of hypotheses**. When an experiment fails or a theory is disproved, document the pivot to the next branch (why the current path failed, what new path is opened).
* **DO** maintain the journal as a **ledger of suspects & validation actions**. Label suspected hypotesis "Unconfirmed" rather than confirmed root causes, and always propose a specific verification action (e.g. executing a run with the suspect commit reverted) to confirm the theory.
* **DO** explicitly catalog downstream symptoms or consequences (like client retry storms or watch cache closures) in a dedicated "Accompanying Symptoms & Red Herrings (Non-Triggers)" section within Section 1 to clearly distinguish them from the actual root cause or trigger.
* **DO** recognize that diagnostic investigations are iterative; the benefit of resolving a bottleneck might be hidden until other dependent bottlenecks are resolved. Always maintain a history of rejected/neutral hypotheses to systematically revisit once the primary bottlenecks shift.
* **DO NOT** treat the exploration journal as an append-only ledger when the benchmark methodology or foundation changes (such as payload size or payload type updates). Instead, remove all obsolete experimental evidence and rebuild/rewrite the existing sections and hypotheses to reflect the new experimental foundation.
* **DO** focus on **comparative results**. Measure experiments against a clean control/baseline state under identical conditions to verify statistical significance (referring to the [benchmarking](../benchmarking/SKILL.md) skill for performance significance, or the [deflaking](../deflaking/SKILL.md) skill for flake reproduction).
* **DO** structure every diagnostic phase or branch with:
  1. **Hypothesis**: The specific theory being tested.
  2. **Arguments & Context**: Rationale for why this hypothesis is mechanically plausible.
  3. **Counter-Arguments / Alternative Explanations**: Alternative reasons for the observed behavior.
  4. **Validation Methodology**: The specific tools, unit tests, delay injections, or configurations used.
  5. **Evidence Collected**: Raw metrics, stack traces, profiles, or differences, compared against the baseline.
  6. **Conclusion / Actions**: Status (Confirmed / Disproved / Unconfirmed) and next steps/pivots.
* **DO NOT** include temporal or project-management details in the status or conclusion fields (e.g. "merged", "reverted", "PR submitted", or "reverted due to complexity"). The journal must remain strictly commit-agnostic and technical, preserving the durable knowledge achieved during exploration (what worked, what failed, and the raw empirical metrics). Project state is transient, whereas diagnostic discovery is permanent.
* **DO NOT** add, commit, or track investigation journal files (or any skill-related files in the .agents/ directory) to the git repository or history without explicit user permission. These files must remain untracked on the workspace.
* **DO** ensure absolute reproducibility for every experiment. The journal must document:
  1. The exact **git commit hash** to checkout.
  2. The precise **execution command** (referring to the execution standards in the [benchmarking](../benchmarking/SKILL.md), [deflaking](../deflaking/SKILL.md), or [testing](../testing/SKILL.md) skills) and package path.
  3. Any **run parameters** (e.g., environment variables, parallelism settings, or setup configs) necessary to recreate the exact testing context and get the same results next time.
  4. Reference raw local profiles, logs, or debug output inside hypothesis-specific subdirectories under `reports/` using relative to workspace `file://` links, or reference remote GCS bucket artifacts using direct storage HTTP links (e.g. `https://storage.googleapis.com/...`), accompanied by a short shell command (e.g., using `curl`, `jq`, or `grep`) to allow others to replicate the validation.

### 2. Domain-Specific Diagnostic Techniques
* **WHEN** investigating performance bottlenecks (e.g., locks, scheduler latency, or CPU profiles), refer to the [optimization](../optimization/SKILL.md) and [benchmarking](../benchmarking/SKILL.md) skills for profiling (pprof), CPU affinity (taskset), and causal profiling standards.
* **WHEN** investigating flaky tests or race conditions, refer to the [deflaking](../deflaking/SKILL.md) skill for stress testing and timing delay injection standards.


### 3. Journal Introduction & Methodology Standards
* **DO** start the journal with a high-level overview detailing:
  1. **Scope & Goals**: The primary symptom, regression, bug, or bottleneck being investigated.
  2. **Target Criteria**: The target indicators, success criteria, or expectations of the exploration.
  3. **Methodology**: Write a dedicated, succinct section detailing the methodology of exploration. Describe the test harness, benchmark, scale framework, or simulation tool. This guarantees future expansions of the journal build on the same baseline. Treat the tool as a black box and document:
    1. **Locations & Design**: Where the test harness or tool is implemented, how it executes workloads, and how it's structured.
    2. **Perks & Downsides (Limitations & Inaccuracies)**: Call out tool constraints (e.g. tail variance, scheduling jitters, lack of external network simulation).
    3. **Polluted or Invalid Metrics/Indicators**: Detail any indicators or metrics that are polluted or skewed by background workloads or concurrency (e.g. ignoring allocation metrics under concurrent reader load), and how to isolate them.
    4. **Data or Environment Setup Skews**: Highlight potential biases introduced by the tool's setup.
    5. **Fast Prototyping (Downscaling)**: Provide actionable recommendations to downscale test sizes (e.g. fewer iterations, smaller object counts) to accelerate local iteration, while requiring full-scale validation before final commits or journal reports.

## Gotchas
* **Git Rebasing**: Force-pushing or rebasing changes historical commit hashes, making previous configurations unreproducible. Always document the baseline commit of your current branch.

## Correct vs. Incorrect Patterns

### Structuring Diagnostic Steps
```markdown
// ❌ INCORRECT: Generic summary without hypothesis, counter-arguments, or reproducible setup
### We fixed the flake
We bypassed the Get call and it runs 20% faster now and doesn't flake.

// ✅ CORRECT: Structured diagnostic journal
### Section 5: Bypassing Initial etcd Read in GuaranteedUpdate
* **Baseline Commit**: `57bbd21c91e` (experiment reverted on this base)
* **Hypothesis**: Bypassing the initial read-only GET request to etcd will significantly speed up writes.
* **Arguments & Context**: Bypassing a network roundtrip (GET) should save 50% of the network latency.
* **Counter-Arguments**: Read-only GET requests are served directly from the in-memory MVCC read buffer without going through Raft consensus, making them extremely fast compared to disk-bound write transactions.
* **Validation Methodology**: Targeted comparative benchmarks over a large dataset (30 runs).
* **Evidence Collected**: Initial small run (10 runs) showed false-positive +30% speedup. However, over 30 runs, the speedup collapsed to completely neutral (~, geomean -1.11% diff).
  * Raw benchmark log: [cacher_1k_nowatch_true.txt](file:///path/to/references/reports/scheduler_contention/cacher_1k_nowatch_true.txt)
* **Conclusion**: Reverted the optimization as it added code complexity for zero performance gain.
```
