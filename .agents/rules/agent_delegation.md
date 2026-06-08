---
name: agent-delegation-standards
description: Rules for orchestrating subagents, parallelizing tasks, managing context handoffs, and isolating high-volume file operations.
globs: ["*"]
tools: [Agent, Read, Write, Bash]
alwaysApply: false
---

# Multi-Agent Delegation & Orchestration

## Goal
Prevent context window bloat and reduce latency by aggressively delegating high-volume, isolated, or parallelizable tasks to specialized subagents. You are the Orchestrator.

## Instructions

### 1. Triggers for Subagent Handoff
* **DO** spawn a subagent for high-volume reads (e.g., scanning the whole codebase, parsing large PDFs, or reviewing server logs).
* **DO** delegate domain-specific tasks (e.g., spawning a "Security Reviewer" agent to audit a newly written module).
* **DO** launch subagents in parallel for independent tracks (e.g., Agent A analyzes frontend, Agent B analyzes database).

### 2. Context Boundaries & Prompting
* **DO** define a strict, narrow scope for each subagent.
* **DO** pass explicit, focused context to the subagent (e.g., a summarized JSON or markdown block). Do not assume they have access to the global conversation history.
* **DO NOT** delegate simple, linear tasks that can be completed in one or two direct tool calls.

### 3. Execution & Synthesis
* **DO NOT** allow multiple subagents to write to the same file concurrently. Subagents should default to "Read-Only" capabilities unless strictly necessary.
* **DO** synthesize subagent outputs into a single, cohesive artifact (e.g., `audit_results.md` or a structured response) rather than forwarding raw subagent logs to the user.

## Integration
* **Expert Persona:** AI Orchestrator.
* **MCP Tools:** None.

## Correct vs. Incorrect Patterns

### Subagent Delegation
```text
❌ INCORRECT (Monolithic)
"I will read all 15 controllers, rewrite deprecated APIs, and verify tests."

✅ CORRECT (Orchestrated)
"I will spawn three parallel subagents to read 5 controllers each and report deprecated API usage. I will synthesize their reports and then edit the files sequentially to prevent write collisions."
```