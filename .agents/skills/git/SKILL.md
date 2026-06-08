---
name: git
description: Standardized procedures for interactive rebasing, history reconstruction, conflict resolution, lock remediation, and atomic commits.
globs: "**/*"
tools: [Read, Write, Edit, Bash]
alwaysApply: true
---

# Git Workflows & Branch Management Standards

## Goal
Maintain an exceptionally clean, logical, and bisectable Git history by enforcing atomic commits, sequential branch rebuilding, lock remediation, and dependency tracking structures.

## Instructions

### 1. Git History Reconstruction & Rebuilding Commit Chains
* **DO** split changes into clean, logical commits using the `git commit --signoff` command once a draft passes all verification tests.
* **DO** amend the original target commit directly to address code-review feedback instead of pushing "fixup" or "comment resolution" commits to the tail of your branch.
* **DO** use a temporary, separate branch to rebuild sequential commit chains by cherry-picking downstream commits step-by-step when reconstructing complex history:
  1. Checkout the parent base commit.
  2. Amend or update base modifications.
  3. Cherry-pick the downstream commit hashes one by one.
  4. Hard-reset your main branch to the temporary branch pointer: `git reset --hard temp-branch-name`.
* **DO** recognize that cherry-picking downstream cleanup commits (`git cherry-pick -n`) can trigger merge conflicts if they modify structures introduced by earlier commits. 
* **DO** resolve these conflicts and ensure a **100% exact one-to-one code match** at the branch tip by leveraging **Orthogonal File Checkouts** during commit reconstruction:
  1. Identify the distinct, orthogonal vertical slices of files modified across your base commits (e.g., `server/storage/`, `server/rafthttp/`, `tests/robustness/`).
  2. Cherry-pick the original migration base commit.
  3. Checkout the exact final version of the files for that specific slice directly from the original branch's final head. **DO NOT** use branch names (which can be ambiguous); use the explicit, immutable **commit hash** of the target branch tip:
     ```bash
     git checkout <original-commit-hash> -- <orthogonal-files-or-directories>
     ```
  4. Amend the commit to incorporate the squashed cleanup:
     ```bash
     git commit --amend --no-edit --signoff
     ```
  This technique guarantees a conflict-free squashing process.
* **DO** always run a full `git diff` between your newly squashed branch tip and the original branch's final commit hash to validate that the resulting outputted code matches exactly (producing a completely empty diff):
  ```bash
  git diff <new-branch-head> <original-commit-hash>
  ```
* **DO** cleanly discard or restore downstream files that conflict during stash-pops on historical base commits:
  ```bash
  git restore --source=HEAD -- <conflicted-file>
  ```
* **DO** specify the fully qualified branch reference `refs/heads/<branch-name>` if git outputs warnings or errors regarding ambiguous refnames (e.g., `warning: refname '...' is ambiguous` or `fatal: ambiguous object name`). This occurs when a local branch has the exact same name as a remote or remote-tracking reference (e.g., `refs/heads/serathius/bump-raft` vs. `refs/remotes/serathius/bump-raft`). To prevent and fix this, reference local branches explicitly via `refs/heads/<branch-name>` or delete/rename the colliding remote/remote-tracking reference.
* **DO** recognize that interactive rebase commands (`git rebase -i`) may fail on automated, dumb terminals with `Terminal is dumb, but EDITOR unset`. Use `GIT_SEQUENCE_EDITOR="cat" git rebase -i` to inspect or run non-interactive rebase scripts.
* **DO NOT** use `git switch refs/heads/<branch-name>` since Git expects a raw branch name (causing `fatal: a branch is expected`). Instead, use `git checkout refs/heads/<branch-name>` to switch to the explicit reference pointer, or switch back to local branch tracking via `git checkout -B <branch-name> HEAD`.

### 2. Remediation of Bisect Metadata & Git Locks
* **DO NOT** struggle with `git bisect reset` errors due to stale bisect files. Directy delete them:
  ```bash
  rm -f .git/BISECT_*
  ```
* **DO NOT** retry git operations indefinitely when seeing `fatal: Unable to create '.../.git/index.lock'`. Forcefully delete the lock file:
  ```bash
  rm -f .git/index.lock
  ```

### 3. Dependency Modifications & Verification Mapping
* **DO** execute matching fix targets immediately inside the same commit that introduces a dependency or configuration modification to ensure each commit remains structurally consistent and standalone (refer to `./COMMANDS.md` for the exact verification and fix mappings).
* **DO NOT** keep `go.mod` tidying, import formatting (GCI), schema testing adjustments, or minor test assertion adaptations as separate "cleanup" commits at the end of a PR branch. Identify the specific upstream commit that modified the dependency or API signature and squash/integrate those modifications directly into that specific commit.

### 4. Committing Performance Changes
* **DO** describe the commit message body succinctly and directly, explaining what changed and the high-level rationale.
* **DO** summarize the key performance differences directly, highlighting the reduction in metric variance and comparison details (e.g. difference of variance between previous vs new approach).
* **DO** include a results summary and the complete, raw `benchstat` comparison results across all metrics (e.g., `sec/op`, `writes/s`, `list-calls/s`, `list-objs/s`, `seconds-delay`) in the commit message when committing performance optimization features.
* **DO NOT** manually truncate, filter, or summarize `benchstat` results by arbitrarily removing lines from a specific benchmark table in the git commit message.
* **DO** use exact `benchstat` filtering (e.g., filtering for specific configurations like `RV=Exact` using `benchstat -filter` or by pre-filtering the raw `.txt` output files to retain only relevant rows and headers) if the optimization specifically targets a subset of workloads, or if certain benchmark suites are proven to be compromised by unrelated environmental noise. Always include the complete tables for the retained scenarios to maintain verification integrity.
## Integration
* **Expert Persona:** Git Historian & Release Manager.
* **MCP Tools:** None.

## Correct vs. Incorrect Patterns

### Conflict Cleanups during Historical Amending
```bash
# ❌ INCORRECT: Leaving downstream conflicts dirty when amending a base commit
git stash pop
# (Conflicts on server/etcdserver/raft.go, server/storage/wal/wal.go)
git commit --amend # Pollution of wal.go additions inside raft.go's base commit!

#  CORRECT: Isolate and discard downstream conflicts before amending
git stash pop
git add server/etcdserver/raft.go
git restore --source=HEAD -- server/storage/wal/wal.go
git commit --amend
```

