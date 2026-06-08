---
name: optimization
description: General principles for performance engineering, resource trade-offs, and avoiding premature or unverified optimizations.
globs: ["**/*.go", "**/*.md"]
tools: [Read, Write, Edit, Bash]
alwaysApply: false
---

# Goal
Provide meta-reasoning guidelines for evaluating and executing performance optimizations to prevent wasted effort on phantom regressions and destructive resource trade-offs under concurrency.

# Instructions

### 1. Evidence-Based Optimization
* **DO NOT** solve "Phantom Problems." Before attempting architectural fixes, performance optimizations, or deep debugging, verify the premise mathematically. For benchmarks, require statistical significance (`p < 0.05`). Misinterpreting noise as a regression guarantees wasted effort.
* **DO** ensure that optimization efforts are targeted at proven bottlenecks identified via profiling (e.g., `pprof`), verified tracing, or statistically sound metric degradation, rather than theoretical improvements.

### 2. Resource Trade-offs & Concurrency
* **DO** evaluate resource trade-offs holistically, especially regarding **Concurrency vs. Complexity**. Optimization is rarely free; measure the "spend" dimension carefully.
* **DO NOT** assume that trading memory allocations for CPU cycles is always a net positive. A localized optimization (e.g., doing a double iteration pass to pre-calculate capacity and avoid slice reallocations) might appear sound in isolation, but can cause catastrophic lock contention or CPU thrashing when exposed to high parallel concurrency. 
* **DO NOT** perform "blind" algorithmic optimizations that increase CPU execution time without explicitly testing the impact on latency under heavy parallel load.

## Integration
* **Expert Persona:** Senior Performance Architect.

## Correct vs. Incorrect Patterns

### Trade-off Evaluation
```go
// ❌ INCORRECT: Blindly adding an O(N) pass to preallocate, increasing CPU contention under high concurrency.
count := list.Count() // First O(N) pass
result := make([]Item, 0, count)
list.Walk(func(item Item) { // Second O(N) pass
    result = append(result, item)
})

// ✅ CORRECT: Measure if the single O(N) pass with background slice growth is actually a bottleneck before "optimizing".
var result []Item
list.Walk(func(item Item) { // Single O(N) pass
    result = append(result, item)
})
```
