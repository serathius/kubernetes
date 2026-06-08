---
name: download-ci-artifacts
description: Download artifacts from a CI run's GCS bucket to local disk.
globs: []
tools: [Read, Write, Edit, Bash]
alwaysApply: false
---

# Goal
Download artifacts from a CI run's GCS bucket to a local directory safely, handling credential constraints.

# Instructions

## 1. Parse URI
* **DO** normalize the input URI: accept gcsweb URLs (`https://gcsweb.k8s.io/gcs/...`), raw `gs://` paths, or Prow job URLs (`https://prow.k8s.io/view/gs/...`).
* **DO** convert gcsweb/Prow URLs to standard GCS paths by replacing `https://gcsweb.k8s.io/gcs/` or `https://prow.k8s.io/view/gs/` with `gs://`.

## 2. Create Local Directory
* **DO** create a local directory using an identifier extracted from the URI (e.g., the Prow build ID) if no output directory is provided.

## 3. Download
* **DO** check if the environment is already authorized for `gcloud storage` by running a fast, timed-out query first (e.g., `timeout 5s gcloud storage ls gs://<bucket>`).
* **DO** ask the user to authorize or refresh their credentials if the `gcloud storage` check fails or times out. Suggest that they run one of these commands in their local terminal:
  - `gcloud auth login` (to log in again)
  - `gcloud auth application-default login` (if Application Default Credentials are missing/outdated)
  - Or simply run a command like `gcloud storage ls gs://<bucket>` in their own local terminal and touch their security key when prompted to refresh the cached session.
* **DO** use `gcloud storage cp` to download the target files or patterns specified by the user (e.g., `etcd.log`, `*.json`, `junit.xml`).

## 4. Report
* **DO** list the files downloaded and their sizes in the summary report.

## 5. Fetching TestGrid Data
* **DO NOT** attempt to grep for `tgData` in TestGrid HTML pages or run `gsutil` on `gs://k8s-testgrid` buckets (which often fail due to credentials).
* **DO** use the included python script `.agents/skills/download-ci-artifacts/scripts/analyze_testgrid.py` to analyze test flakes and extract Prow Build IDs for failures instead of writing a new script from scratch.
  - Example: `python3 .agents/skills/download-ci-artifacts/scripts/analyze_testgrid.py --dashboard sig-etcd-main-periodics --tab ci-etcd-integration-1-cpu-amd64`
  - Example: `python3 .agents/skills/download-ci-artifacts/scripts/analyze_testgrid.py --dashboard sig-etcd-main-periodics --tab ci-etcd-integration-1-cpu-amd64 --test-name "TestRevisionMonotonicWithLeaderRestarts"` to get the exact `Failed Build IDs`.
* **DO** map the status values correctly if you ever parse it manually: `0`=NO_RESULT, `1`=PASS, `4` or `12`=FAIL, `13`=FLAKY.

## Integration
* **Expert Persona:** CI/CD Integration & Test Grid Engineer.
* **MCP Tools:** None.
