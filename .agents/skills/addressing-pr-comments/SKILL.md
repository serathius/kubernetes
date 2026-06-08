---
name: addressing-pr-comments
description: Best practices for tracking complex multi-staged pull request comments, checklists, and roadmap checkpoints.
globs: ["**/*.json", "**/*.md"]
tools: [Read, Write, Edit, Bash]
alwaysApply: false
---

# PR Roadmap & Session Tracking Workflows

## Goal
Enable organized, error-free tracking of complex PR code reviews by mapping raw review comments into local, staged checklists separated by technical complexity.

## Instructions

### 1. Staged Complexity Roadmap Creation
* **DO** download raw pull request comments into local JSON structures inside your private conversational brain folder (e.g., `/usr/local/google/home/siarkowicz/.gemini/jetski/brain/<conversation_id>/comments_raw.json`).
* **DO** construct a roadmap checklist file named `pr_review_tracking.md` or `pr_<PR>_comments.md` exclusively in your private local brain workspace.
* **DO NOT** check in, commit, or track general tracking or roadmap checklists inside the repository's public Git version control.
* **DO** order review comments into sequential checks sorted by ascending difficulty:
  1. **Tier 1 (Direct/Inline):** Pointer allocations, formatting, import blocks, local lints.
  2. **Tier 2 (Medium Assertions):** Unit and integration test stubs, mock verifications.
  3. **Tier 3 (Complex Loops):** Core synchronization engines, consensus invariants, locking schemas.
* **DO** group the roadmap checklist strictly into three sequential phases:
  * **Stage 1 (Trivial / Non-Ambiguous):** Direct inline refactors that compile cleanly.
  * **Stage 2 (Non-Trivial / Medium Complexity):** Test suites, marshaling helpers, and deep-equal changes.
  * **Stage 3 (Ambiguous / High Complexity):** Unclear structural changes requiring user input.

### 2. Execution & Resync Workflow
* **DO** solve comments tier-by-tier and stage-by-stage, verifying compilation and test completion before progressing.
* **DO NOT** mix ambiguous Stage 3 comments into active Stage 1 tasks. Keep them completely isolated to avoid blocking progress.
* **DO NOT** claim complete success or summarize accomplishments if there are review threads marked as **Postponed** or **Deferred** in the tracking roadmap.
* **DO** explicitly list unresolved or deferred comments requiring user guidance in your status updates.
* **DO** execute API resyncs to update active comment states before starting new tiers.

## Integration
* **Expert Persona:** Lead QA Engineer & PR Coordinator.
* **MCP Tools:** None.

## Correct vs. Incorrect Patterns

### Roadmap Tracking Format
```markdown
# PR #12345 Review Tracking

| ID | File | Line | Actionable Item | Status | Done? |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **3292537128** | `server/etcdserver/server.go` | 1405 | Use inline new allocations | ⏳ Pending | [ ] |
```
