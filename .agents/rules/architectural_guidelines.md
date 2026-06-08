---
name: architectural-guidelines
description: Directory tree macro layout, Step-down ordering rule, comments policy, and AI-agent behaviors for Go.
globs: "**/*.go"
tools: [Read, Write, Edit, Bash]
alwaysApply: true
---

# Architectural Guidelines

## Goal
These standards govern directory structures, code layout within files, documentation, and AI-agent interactions inside Go files. They ensure high cohesion, clear narrative flow, clean reviewable structures, and predictable multi-agent collaboration.

## Instructions

### 1. Directory Architecture (Macro)
* **DO** mirror the logical hierarchy of the application domain, not the web framework.
* **DO** ensure every directory solves a single, well-defined problem (Bounded Contexts) to avoid parallel AI agent merge conflicts.
* **DO** prioritize keeping code that changes together in the same directory (Locality of Behavior).
* **DO** treat a module `B` as a "Private Implementation Detail" of `A` and move it into a subdirectory of `A` if `A` is the exclusive dependent.
* **DO NOT** use generic "drawer" directories (e.g., `utils`, `common`, `helpers`). Group generic logic by its specific technical domain.
* **DO NOT** separate files purely by "File Type" (e.g., placing all controllers in one folder and all models in another).

### 2. Internal File Organization (Micro)
* **DO** break large files into smaller units. If a specific set of functions constitutes a separate logical unit, extract them to a new file.
* **DO** follow the Step-down Rule: organize code sequentially (Public API first, then Narrative Flow, then Details Last).

### 3. Comments & Documentation
* **DO** write comments *only* to explain **why** a certain path, constraint, or design was taken.
* **DO** rely on explicit naming conventions and robust code structure over inline comments (Self-Documenting Code).
* **DO** write standard `// SymbolName ...` comments for exported APIs.
* **DO NOT** explain *what* the code is doing. Refactor the structure instead.

### 4. AI Agent & Antigravity Workflow Rules
* **DO** halt and analyze the root cause when debugging. Attempt a maximum of one fix at a time. Never apply a workaround to bypass an underlying architectural flaw.
* **DO** output a brief technical plan outlining which Bounded Contexts will be touched before modifying the codebase.
* **DO** ensure all generated Go tests do not rely on shared global state or hardcoded file paths (Parallel-Safe Testing).

### 5. Functional Design & Reuse
* **DO** split complex operations into small, simple, and flat sub-functions, each achieving a single goal of abstraction with clear guard clauses.
* **DO** prefer wrapping or decorating existing function fields/handlers to achieve test/feature goals without modifying production code.
* **DO NOT** accumulate complex telemetry tracking, parameter parsing, or heavy execution steps into a single giant function (God Functions).
* **DO NOT** design new hook configurations or unexported fields in production files before verifying if existing structures can be leveraged.

## Integration
* **Expert Persona:** Go System Architect.
* **MCP Tools:** None.

## Correct vs. Incorrect Patterns

### Directory Structure
```text
❌ INCORRECT
/utils
  /math.go
  /strings.go

✅ CORRECT
/mathutil
  /mathutil.go
/stringsvc
  /stringsvc.go
```