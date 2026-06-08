---
name: github
description: Workflows for retrieving pull request comments, reviews, and thread status programmatically using gh and jq.
globs: ["**/*.json", "**/*.md"]
tools: [Read, Write, Edit, Bash]
alwaysApply: false
---

# GitHub API Integration Standards

## Goal
Ensure fast, reliable, and programmatic synchronization of PR reviews and timeline comments via GitHub's API endpoints using CLI integrations rather than fragile UI scraping.

## Instructions

### 1. Pull Request Comments & Discussions Extraction
* **DO** query both pull request review comment and issue issue comment endpoints to gather all feedback.
* **DO** use the following `gh api` commands to parse line-specific and general timeline comments cleanly with `jq`:
  
  **Line-Specific / Review Comments:**
  ```bash
  gh api repos/OWNER/REPO/pulls/PR_NUMBER/comments --paginate --jq '.[] | {id: .id, path: .path, line: (.line // .original_line), author: .user.login, body: .body}'
  ```
  
  **General Timeline / Issue Comments:**
  ```bash
  gh api repos/OWNER/REPO/issues/PR_NUMBER/comments --paginate --jq '.[] | {id: .id, author: .user.login, body: .body}'
  ```

### 2. Thread Resolution Tracking
* **DO NOT** use browser automation or scraping to discover resolved threads.
* **DO** track thread state programmatically. The `/pulls/PR_NUMBER/comments` API endpoint returns only unresolved active comment threads. Any comment ID that is absent from this list but was present historically has been resolved.

## Integration
* **Expert Persona:** GitHub Integration Specialist.
* **MCP Tools:** None.

## Correct vs. Incorrect Patterns

### Verifying Comments Programmatically
```bash
# ❌ INCORRECT: Navigating via a browser subagent to manually read resolved ticks
# Open browser, wait, scroll, verify ticks. (Very slow, brittle)

#  CORRECT: Fast API assertion of active threads
gh api repos/etcd-io/etcd/pulls/21778/comments | jq '.[].id'
```
