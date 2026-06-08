---
name: development
description: Guides Go compilation using GOROOT overrides, strict GCI import ordering, and Go 1.26 direct pointer allocations.
globs: ["**/*.go", "go.mod"]
tools: [Read, Write, Edit, Bash]
alwaysApply: false
---

# Go Development & Tooling Standards

## Goal
Ensure highly robust, compile-safe, and lint-compliant Go development by enforcing GOROOT compilation overrides, gci style configurations, and modern Go 1.26 memory allocation constructs.

## Instructions

### 1. Toolchain and Compilation Override
* **DO** always prefix all build, test, and validation commands with `GOROOT=""` to guarantee Go cleanly resolves to the active workspace toolchain, avoiding compiler version mismatch failures in multi-toolchain environments.

### 2. Code Styling and Import Formatting (gci)
* **DO** separate import blocks into exactly three blocks separated by single empty newlines:
  1. Standard Library (e.g., `testing`, `time`)
  2. Third-Party Default (e.g., `github.com/stretchr/testify/require`)
  3. Repository Prefix (e.g., `go.etcd.io/raft/v3/raftpb`)
* **DO NOT** group third-party imports and repository prefix (`go.etcd.io`) imports into a single block.
* **DO NOT** leave duplicate empty newlines or trailing empty newlines at the end of files, which trigger strict `gci` verification lints.

### 3. Go 1.26 Pointer Allocation Standards
* **DO** use the built-in `new(expression)` construct directly to allocate heap memory and initialize values in a single inline expression (e.g., `new(uint64(1))`).
* **DO NOT** create local temporary variables (e.g., `membID := uint64(1); &membID`) solely to take their reference.
* **DO NOT** wrap a source variable inside a redundant conversion constructor (e.g., `new(uint64(idx))` when `idx` is already a `uint64`). Use `new(idx)` directly to prevent `unconvert` lints.
* **Go 1.26 Compiler Allocation Optimization Note:** 
  * Historically (pre-Go 1.26), `new(Type)` only accepted a Type name (e.g. `new(uint64)`), forcing developers to use external helpers (e.g., `proto.Uint64(3)`) or local pointer variables to initialize structures. In Go 1.26, `new(expression)` is fully natively supported by the compiler.
  * The Go compiler optimizes `new(expression)` identically to local value address-of operations (`&val`). It applies standard escape analysis under the hood; if the allocated pointer does not escape the function scope, it allocates the memory on the stack rather than the heap, completely avoiding GC allocation barriers.
  * Passing a variable already matching the target type to `new()` as a conversion (e.g., `new(uint64(idx))` when `idx` is already `uint64`) triggers `unconvert` static check diagnostics, whereas using `new(idx)` is treated as a clean, zero-overhead pointer construction.

### 4. License and Header Standards
* **DO** always include the Apache 2.0 License header at the very top of every newly created Go file in the repository.
* **DO** explicitly specify the **current calendar year** (e.g., `2026`) inside the `Copyright <Year> The etcd Authors` line of the license header for all newly created files.

### 5. Validation-Driven Development & Path Verification
* **DO NOT** assume a code path is executed when refactoring or modifying complex flows, especially those involving interface boundaries, wrappers, or indirect hooks.
* **DO** practice validation-driven development: inject a deliberate panic, error, or log statement (e.g., `panic("target path reached")`) directly into the target code block.
* **DO** verify that the test suite or local runner catches this failure before you write the final business/optimization logic. This guarantees you are building on top of a verified path rather than an unexercised assumption.

### 6. Code Formatting Verification (Gofmt)
* **DO** always run formatting verification scripts or local style check linters to ensure code formatting compliance before concluding any task (refer to `./COMMANDS.md` for specific repo commands).
* **DO** use formatting fix scripts to automatically resolve style non-compliance (refer to `./COMMANDS.md` for the specific command).

## Integration
* **Expert Persona:** Senior Go Compiler & Toolchain Engineer.
* **MCP Tools:** None.

## Correct vs. Incorrect Patterns

### Imports Formatting
```go
// ❌ INCORRECT
import (
    "testing"
    "github.com/stretchr/testify/require"
    "go.etcd.io/raft/v3/raftpb"
)

//  CORRECT
import (
    "testing"
    "time"

    "github.com/stretchr/testify/require"

    "go.etcd.io/raft/v3/raftpb"
)
```

### Go 1.26 Pointer Allocation
```go
// ❌ INCORRECT
id := uint64(1)
member := &Member{
    ID: &id,
}

// ❌ INCORRECT
idx := uint64(5)
val := new(uint64(idx))

//  CORRECT
member := &Member{
    ID: new(uint64(1)),
}
```

### GCI Named Imports & Alignment
```go
// ❌ INCORRECT (gci sorts raw block, removing override alignment)
import (
    bolt "go.etcd.io/bbolt"
    "go.etcd.io/etcd/api/v3/etcdserverpb"
)

//  CORRECT
import (
    bolt "go.etcd.io/bbolt"

    "go.etcd.io/etcd/api/v3/etcdserverpb"
)
```



