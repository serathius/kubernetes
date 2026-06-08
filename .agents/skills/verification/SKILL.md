---
name: local-verification-workflows
description: Workflow optimizations for running linting checks, test speedups, and comparing protobuf structural assertions.
globs: ["Makefile", "**/*.go"]
tools: [Read, Write, Edit, Bash]
alwaysApply: true
---

# Verification Workflows & CLI Speeds

## Goal
Accelerate iterative development verification using focused static analysis while securing crash-safe, high-performance protobuf and heavy payload assertions.

## Instructions

### 1. Validation Workflow Speed Optimizations
* **DO** optimize your feedback loop by running targeted static checks instead of the full 14-stage aggregate verification (refer to `./COMMANDS.md` for specific repo commands like lint or mod tidy verification).
* **DO NOT** run global aggregate fix commands when a subrule check fails. Execute the targeted subrule fix directly (refer to `./COMMANDS.md` for specific fix commands) to prevent unnecessary modification of files outside your bounded context.
* **DO** execute the full validation pipeline only as a final pre-push sanity verification step (refer to `./COMMANDS.md` for the exact pipeline).

## Integration
* **Expert Persona:** Verification & Build System Engineer.
* **MCP Tools:** None.

## Correct vs. Incorrect Patterns

### Targeted Fixes
```bash
# ❌ INCORRECT: Running the global aggregate fix command
GOROOT="" make fix

# ✅ CORRECT: Running the targeted subrule fix directly
GOROOT="" make fix-lint
```
