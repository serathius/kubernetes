---
name: testing
description: Standard patterns for writing Go unit tests, mock/stub setups, copylocks lint resolution, and high-performance heavy payload assertions.
globs: "**/*_test.go"
tools: [Read, Write, Edit, Bash]
alwaysApply: false
---

# Go Testing & Verification Standards

## Goal
Ensure high-performance, clean, and lint-compliant Go testing by enforcing strict mocking parameters, eliminating redundant production nil-guards, avoiding copylock value copies, and optimizing deep comparisons.

## Instructions

### 0. Reproduction First Principle
* **DO NOT** write or propose any fix before establishing a local reproduction of the bug (either by running the existing failing test locally or writing a new reproducing unit test). This ensures you have identified the exact root cause and can verify the fix correctly.

### 1. Testing and Mock/Stubbing Principles
* **DO NOT** "protect" the production code path by adding defensive runtime checks (e.g., `if storage != nil`) simply to accommodate lazy unit test setups. Fix the unit test configurations instead.
* **DO** always check for and reuse existing test helper functions, stubs, fixtures, and mock wrappers rather than duplicating setup logic or re-writing test harnesses. This guarantees high cohesion and keeps tests dry and bisectable.

### 2. Standard Test Assertions & Comparisons
* **DO** utilize generic pointers, marshaled byte arrays, or standard testing libraries (`require.Equal` / `reflect.DeepEqual`) directly inline inside test code.
* **DO NOT** write ad-hoc, custom struct assertion loop functions for each unique struct data type comparison.
* **DO NOT** execute deep comparisons (`cmp.Diff` or `cmp.Equal`) directly on massive datasets (e.g., >10MB WAL slices). Recursive checking on giant trees causes combinatorial execution paths and test timeouts.
* **DO** optimize heavy payload comparisons by verifying slice sizes first, comparing payload fields directly inside a fast loop using `bytes.Equal`, and stripping data contents (`Data = nil`) prior to structural comparisons.

### 3. High-Performance Client Mocking & Concurrency Deadlock Avoidance
* **DO NOT** spin up heavy in-process clusters (e.g., `integration.NewCluster` or `e2e`) to unit-test clients or wrappers.
* **DO** leverage the fact that `clientv3.Client` embeds its service layers (`Watcher`, `KV`, `Lease`, etc.) as interfaces. Override these embedded interface fields directly using `clientv3.NewCtxClient(ctx)` and struct literals for connectionless, ultra-fast in-memory mocks.
* **DO** make mock channels (e.g., watch channels) buffered (e.g., `capacity 10`) to completely decouple asynchronous goroutine startup from execution.
* **DO** ensure mock goroutines are cleanly unblocked and exited by cancelling contexts and closing channels before running assertions or `wg.Wait()`.

## Integration
* **Expert Persona:** Go Quality Assurance & Mocking Architect.
* **MCP Tools:** None.

## Correct vs. Incorrect Patterns

### Loop Copylocks Resolution
```go
// ❌ INCORRECT
for _, tc := range tcs { // Value copy duplicates mutexes inside tc
    t.Run(tc.name, func(t *testing.T) { ... })
}

//  CORRECT
for i := range tcs {
    tc := &tcs[i]
    t.Run(tc.name, func(t *testing.T) { ... })
}
```

### Inline Assertions
```go
// ❌ INCORRECT
func assertMessagesEqual(t *testing.T, expected, actual []raftpb.Message) {
    if len(expected) != len(actual) {
         t.Errorf("mismatch: expected %d, got %d", len(expected), len(actual))
    }
    for i := range expected {
         if expected[i].Type != actual[i].Type {
              t.Errorf("type mismatch at index %d", i)
         }
    }
}

//  CORRECT
require.Equal(t, expectedMessages, actualMessages)
```

### Heavy Array / WAL Payload Assertions
```go
// ❌ INCORRECT
if diff := cmp.Diff(largeWALEntriesA, largeWALEntriesB); diff != "" { // Combinatorial explosion; timeouts in CI
    t.Fatal(diff)
}

//  CORRECT
if len(largeWALEntriesA) != len(largeWALEntriesB) {
    t.Fatalf("length mismatch: %d != %d", len(largeWALEntriesA), len(largeWALEntriesB))
}
for i := range largeWALEntriesA {
    if !bytes.Equal(largeWALEntriesA[i].Data, largeWALEntriesB[i].Data) {
        t.Fatalf("Data payload mismatch at index %d", i)
    }
    // Verify structural metadata after stripping raw payload data:
    largeWALEntriesA[i].Data = nil
    largeWALEntriesB[i].Data = nil
    if diff := cmp.Diff(largeWALEntriesA[i], largeWALEntriesB[i], cmpopts.IgnoreUnexported(raftpb.Entry{})); diff != "" {
        t.Fatal(diff)
    }
}
```

### In-Memory Client Mocking
```go
// ❌ INCORRECT (Slow and heavy, startup overhead >5s)
func TestWatchWrapper(t *testing.T) {
    clus := integration.NewCluster(t, &integration.ClusterConfig{Size: 1})
    defer clus.Terminate(t)
    c := NewWatchWrapper(clus.Client(0))
    ...
}

//  CORRECT (Connectionless, fully in-memory, execution time <1ms)
type mockWatcher struct {
    ch chan clientv3.WatchResponse
}
func (m *mockWatcher) Watch(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan {
    return m.ch
}
func (m *mockWatcher) RequestProgress(ctx context.Context) error { return nil }
func (m *mockWatcher) Close() error { return nil }

func TestWatchWrapper(t *testing.T) {
    watchChan := make(chan clientv3.WatchResponse, 10) // Buffered!
    watcher := &mockWatcher{ch: watchChan}
    
    cc := clientv3.NewCtxClient(context.Background())
    cc.Watcher = watcher // Interface override
    
    c := NewWatchWrapper(cc)
    ...
    
    cancel()
    close(watchChan) // Exits range loop
}
```

### 4. Behavior Optimization & Ingestion Validation (Incremental Testing)
* **DO NOT** assume a code path (such as lazy decoding, routing, or proxy layers) is executed simply because it is wired up in indirect wrappers or interface boundaries.
* **DO** validate your path-execution assumption first by injecting a deliberate panic or failing assertion (e.g., `panic("lazy decoding triggered")`) into the target optimization code.
* **DO** run the corresponding test suite and ensure that the test fails or catches the expected panic. Only once the execution path is verified should you remove the panic and build the optimization behavior.

### 5. Robustness Test Reproduction & Verification
* **DO NOT** rely solely on the go test `-run` flag when trying to reproduce a robustness test failure that occurred under a specific scenario. The test runner configures options (such as version choices and failpoints) randomly or conditionally before the test is named.
* **DO** temporarily isolate the target failpoint and scenario in the test harness setup during local reproduction:
  1. Restrict the list of failpoints to only the target failpoint (e.g., in `tests/robustness/failpoint/failpoint.go`).
  2. Override random weight choices (like mixed version choices in `scenarios.go`) to ensure the target setup is always chosen.
  3. Bypass state constraints (such as `SnapshotCatchUpEntries` limits or peer TLS checks in `Available()`) if they would prevent the failpoint from being available in the test scenario.
* **DO** restore/revert all temporary test runner changes using `git checkout` after the reproduction and fix are verified.

### 6. Protobuf Error Checking
* **DO NOT** use brittle string parsing (e.g. `strings.Contains(err.Error(), ...)`) to assert or check for protobuf unmarshaling/marshaling errors. Protobuf error message formats frequently change between Go/library toolchains.
* **DO** check for protobuf runtime errors using `errors.Is(err, proto.Error)`. All parsing and validation errors returned by `google.golang.org/protobuf/proto` safely unwrap to `proto.Error`.

### 7. Layering and Designing Tests (Black-box vs. White-box)
* **DO** layer tests logically to cover different levels of abstraction:
  - **Round-Trip Tests**: Direct tests verifying serialization/parsing format invariants.
  - **Component/Logic Tests**: Verifying computation, calculation, and index math (using mock clocks to simulate behavior).
  - **Integration/System Tests**: End-to-end telemetry and validation pipelines.
* **DO NOT** write unit tests that inspect unexported internal collections or fields directly, or copy internal structures to check private state.
* **DO** prefer black-box assertions that verify correctness by calling clean public API retrieval methods (e.g., `GetP99Latency()`).







