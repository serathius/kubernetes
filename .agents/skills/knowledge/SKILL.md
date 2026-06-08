---
name: knowledge
description: Standards and lifecycle rules for creating modular AI skills, writing precise semantic triggers, defining YAML metadata, and formatting `.gemini` or `.agents` rules.
globs: ["**/.agents/**/*", "**/.gemini/skills/**/*.md"]
tools: [Read, Write, Edit, Bash]
alwaysApply: false
---

# Knowledge & Skill Management Standards

## Goal
Maintain a precise, lean, and highly triggerable library of specialized capabilities (skills) for the AI environment by enforcing strict metadata schemas, single-responsibility limits, and file lifecycles.

## Instructions

### 1. Layered Context Architecture
* **DO** structure codebase guidance across four layers to prevent prompt clutter:
  1. **Universal Rules (`AGENTS.md`):** Global, passive constraints loaded always.
  2. **Specialized Skills (`SKILL.md`):** Targeted, domain-specific instruction sheets dynamically matched by semantic triggers.
  3. **Repository Command Mappings (`./COMMANDS.md`):** Concrete commands mapping to abstract workflows (building, testing, linting), keeping SKILLs repository-agnostic.
  4. **Workflows:** Execution-heavy CLI and helper scripts.

### 2. Identifying Skill Triggers (One Skill = One Responsibility)
* **DO** adhere strictly to the "One Skill = One Responsibility" principle to prevent confusing the AI routing engine. Overlapping skills degrade model performance.
* **DO** create new modular skills immediately when:
  1. **Repetitive Mistakes:** An architectural linter or compiler error is repeated.
  2. **Command Clutter:** Complex chain command lines are executed successfully and repeatedly.
  3. **Opaque Learning:** High-value external PDFs, transcripts, or logs are shared.
  4. **Divergence:** A single skill begins spanning unrelated domains or toolsets.
* **DO** reconsider which skill best matches a new learning before adding it. If a learning doesn't cleanly fit an existing skill's core domain, propose creating a new skill rather than cluttering an existing one.
* **DO** proactively refactor skills by moving points between them based on what they best match. For example, if algorithmic complexity rules end up in a `benchmarking` skill, move them out into an `optimization` skill. While related, they are separate skills.

### 3. Modular Skill Design Standards
* **DO** format every skill with the standard ecosystem structure:
  * YAML metadata header (`name`, `description` [CRITICAL: use semantic trigger keywords], `globs`, `tools`, `alwaysApply`).
  * `# Goal`
  * `# Instructions` (use absolute, positive "DO" and "DO NOT" directives; avoid passive "should" or "could").
  * `# Integration` (Specify required MCP servers, expert personas, or agent hand-offs if applicable).
  * `# Correct vs. Incorrect Patterns` (with minimal, clear comparison code blocks).
* **DO** generalize learnings into broad principles rather than hyper-specific rules that clutter a skill. For example, instead of adding a rigid algorithmic rule against double-pass slice preallocation directly into a `benchmarking` skill, extract the broader meta-reasoning principle (e.g., "Resource Trade-offs and Concurrency") into a dedicated `optimization` or architectural skill.

### 4. Indexing, Preservation, and Git Security
* **DO** register new skill links under the `📂 Modular Standards & Guidelines Directory` in `AGENTS.md`.
* **DO NOT** delete technical rules or historical summaries. Move deprecated items to a temporary review archive file before deletion.
* **DO NOT** add, track, or commit any local `.agents/` or `.gemini/` folder files into public version control unless they are template defaults.
* **DO** locate `.agents/` or `.gemini/` files via explicit directory listing (`list_dir` or bash scripts) rather than general search tools, as they are often gitignored.

## Integration
* **Expert Persona:** AI Tooling & System Prompt Architect.
* **MCP Tools:** None.

## Correct vs. Incorrect Patterns

### Skill File Design Layout
```yaml
# ❌ INCORRECT: Brittle metadata triggers, missing tool context, and overlapping responsibilities.
---
name: code-rules
description: Some files to check and lint code.
---
When writing code, you should consider using pointers.

# ✅ CORRECT: Highly detailed semantic trigger, declared tools, and standard SKILL format.
---
name: go-pointer-allocations
description: Triggers inline pointers and structs using Go 1.26 new allocation rules.
globs: "**/*.go"
tools: [Read, Write, Edit]
alwaysApply: false
---
# Goal
Optimize allocation efficiency using zero-allocation paradigms.

# Instructions
* **DO** allocate inline pointers...
