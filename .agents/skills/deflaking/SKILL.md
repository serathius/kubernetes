---
name: deflaking
description: Detailed workflows for reproducing and deflaking Go tests, injecting timing delays, stress testing with 'stress', and avoiding brittle test patterns.
globs: "**/*_test.go"
tools: [Read, Write, Edit, Bash]
alwaysApply: false
---

# Test Deflaking & Stress Testing Standards

## Goal
Establish a reproducible, statistically significant baseline to verify, isolate, and permanently resolve flaking tests in the codebase using delay injection, parallel stress testing, and robust assertions.

## Instructions

### 1. The Deflaking Mindset
* **DO NOT** assume a flake is always infrastructure or "test-only." Investigate and verify the exact root cause before patching.
* **DO NOT** guess the failure mechanism or panic reason based solely on static analysis. Always download and inspect the exact CI failure logs to see the specific line and error that failed.
* **DO** verify a component is designed to operate asynchronously before introducing polling.
* **DO** isolate latency issues before adjusting timeouts. Fix performance bugs rather than expanding timing margins.
* **DO NOT** alter assertions to bypass concurrency failures if it weakens the validity of the test.
* **DO** distinguish between `require` (which aborts execution) and `assert` (which marks the test as failed but continues execution). A failed `assert` inside a loop will allow the test to continue running, potentially masking the real point of failure in the final test duration.

### 2. Establishing a Reproducible Baseline & Verification Workflow
* **DO** perform cross-branch validation. If a test is flaky on a release branch, verify if it also flakes on `main` via TestGrid. If it does not flake on `main`, use `git log` on the test file to identify if a recent PR already fixed the issue rather than reinventing a solution.
* **DO** verify public CI test flakiness by consulting TestGrid data to determine the actual flake ratio before spending effort on local reproduction. This helps prioritize deflaking efforts based on real-world CI impact.
* **DO** calculate the flake ratio by querying the TestGrid JSON endpoint (see `download-ci-artifacts` skill), counting valid test outcomes (`PASS=1`, `FAIL=4/12`, `FLAKY=13`), and ignoring `NO_RESULT` (0) statuses. The ratio is `(failed + flaky) / (passed + failed + flaky)`.
* **DO** establish a solid, local reproduction baseline before attempting to write a fix.
* **DO NOT** assume your local machine is simply "too fast" if `stress` cannot reproduce a flake. First, verify if the branch you are on actually contains the bug, and ensure your hypothesized root cause is mechanically possible.
* **DO** bypass Go test caching by always executing tests with `-count=1`.
* **DO** inject intentional delays (`time.Sleep`) in production or client code to force timing windows open and recreate race conditions.
* **WARNING**: When using `stress` on end-to-end (`e2e`) tests that rely on hardcoded ports or fixed directories, **DO NOT** use `-p > 1` (parallel execution). Doing so will cause port collisions (`bind: address already in use`), resulting in immediate, false-positive failures and potential data races that obfuscate the original flake. For such tests, always run sequentially (`stress -p 1`). Note that `integration` tests dynamically allocate ports (e.g. `127.0.0.1:0`) and are generally safe for parallel stress testing.
* **DO** compile target package test binaries with the race detector enabled (`-race -c`) and run under the `stress` tool.
* **DO NOT** let `stress` write failure logs to `/tmp/` (its default behavior). Always override the output path using `-o` to write logs to a workspace-local scratch directory to prevent filling up the system `/tmp/` partition and to keep artifacts accessible within the project workspace:
  ```bash
  stress -p 8 -o ./scratch/go-stress- ./etcdserver.test -test.run=TestName -test.timeout=10s
  ```
* **DO** mathematically verify the impact of your change:
  1. **Baseline Run:** Run the flaky test under stress to calculate the baseline error rate (failures / total runs).
  2. **Post-Fix Run:** Rerun the exact same stress setup after applying the proposed fix.
  3. **Evaluate:** Compare rates. **Reject your hypothesis** if the error rate does not drop significantly.
  4. **Document:** Provide the side-by-side stress comparisons when presenting the fix.

### 3. Debugging Deadlocks & Timeout Failures
* **DO** run individual tests to determine their average successful runtime.
* **DO** stress-test the individual test with a tight timeout limit set to ~100x its average successful runtime to fail quickly.
* **DO** force a stack trace dump when a deadlock or hang occurs under stress using `SIGQUIT` (e.g., by sending a `kill -QUIT <pid>` signal to the test process or executing with `Ctrl+\` in a manual run terminal) to instantaneously locate blocked goroutines and channels.
* **DO** instrument blocked code with structured debug logs around channels, locks, and goroutines.

### 4. Avoiding Common Test Anti-Patterns
* **DO NOT** assert on ordering from standard Go map iterations. Sort the keys or values beforehand.
* **DO NOT** use tight timing tolerances (e.g., `100ms` or `500ms`) in test assertions. Use highly tolerant boundaries or event-driven synchronization.
* **DO NOT** hardcode static TCP ports or fixed directories. Use `:0` for port allocation, and dynamically generated temp directories.

## Integration
* **Expert Persona:** Concurrency & Test Reliability Engineer.
* **MCP Tools:** None.

## Correct vs. Incorrect Patterns

### Port and Directory Allocation
```go
// ❌ INCORRECT
listener, err := net.Listen("tcp", "127.0.0.1:2379")
dir := "/tmp/etcd-test-data"

//  CORRECT
listener, err := net.Listen("tcp", "127.0.0.1:0")
dir, err := os.MkdirTemp("", "etcd-test-data")
```

### Map Iteration Asserts
```go
// ❌ INCORRECT
results := make([]string, 0)
for k, v := range myMap {
    results = append(results, v)
}
assert.Equal(t, []string{"A", "B"}, results) // Non-deterministic!

//  CORRECT
results := make([]string, 0)
for k, v := range myMap {
    results = append(results, v)
}
sort.Strings(results)
assert.Equal(t, []string{"A", "B"}, results)
```

### 5. Platform-Specific Debugging (Background vs. Synchronous Execution)
* **DO NOT** rely on background tasks to capture large test failure logs if the platform VM/workspace rolls back or resets files on retrying failed tasks.
* **DO** run test iterations **synchronously** (e.g. by setting `WaitMsBeforeAsync` up to `10000ms`, or running one iteration at a time synchronously) when you need to ensure log files are persisted on disk upon failure without VM state resets.
* **DO** redirect large debug outputs (which can easily exceed thousands of lines when `EXPECT_DEBUG=true` is set) to a local file, and then inspect the file locally using `view_file` to prevent terminal output truncation.
* **DO** use direct HTTP endpoints (like `gcsweb.k8s.io`) and the `read_url_content` tool to fetch CI artifacts when authentication/credential keys (like `gcloud storage`) are blocked or hang due to platform security configurations.

