#!/usr/bin/env bash

# Copyright The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Reproduces a historical storage correctness bug by reverting its fix, running
# the correctness suite, and restoring the tree afterwards.
#
# The suite is expected to FAIL while the patch is applied. This script inverts
# the exit code accordingly: it succeeds when the bug was detected and fails
# when it was not, so that losing detection power is itself a build failure.

set -o errexit
set -o nounset
set -o pipefail

KUBE_ROOT=$(dirname "${BASH_SOURCE[0]}")/../..
source "${KUBE_ROOT}/hack/lib/init.sh"

REPRODUCTIONS_DIR="${KUBE_ROOT}/test/integration/apiserver/storage/reproductions"
WHAT="./test/integration/apiserver/storage"
COUNT="${COUNT:-1}"

list_reproductions() {
  local patch
  for patch in "${REPRODUCTIONS_DIR}"/*.patch; do
    [[ -e "${patch}" ]] || continue
    echo "  ISSUE=$(basename "${patch}" .patch)"
  done
}

if [[ -z "${ISSUE:-}" ]]; then
  kube::log::error "ISSUE is required, for example: make test-correctness-reproduction ISSUE=58545"
  kube::log::error "Available reproductions:"
  list_reproductions
  exit 1
fi

PATCH_FILE="${REPRODUCTIONS_DIR}/${ISSUE}.patch"
if [[ ! -f "${PATCH_FILE}" ]]; then
  kube::log::error "No reproduction patch for issue ${ISSUE} at ${PATCH_FILE}"
  kube::log::error "Available reproductions:"
  list_reproductions
  exit 1
fi

if ! git -C "${KUBE_ROOT}" apply --check "${PATCH_FILE}" 2>/dev/null; then
  kube::log::error "Patch ${PATCH_FILE} does not apply cleanly."
  kube::log::error "The fix it reverts has likely moved. Refresh the patch and update the"
  kube::log::error "track record in test/integration/apiserver/storage/README.md."
  exit 1
fi

PATCH_APPLIED=
cleanup() {
  if [[ -n "${PATCH_APPLIED}" ]]; then
    kube::log::status "Reverting reproduction patch for issue ${ISSUE}"
    git -C "${KUBE_ROOT}" apply -R "${PATCH_FILE}"
    PATCH_APPLIED=
  fi
}
trap cleanup EXIT

kube::log::status "Applying reproduction patch for issue ${ISSUE}"
git -C "${KUBE_ROOT}" apply "${PATCH_FILE}"
PATCH_APPLIED=1

kube::log::status "Running correctness suite (expected to fail)"
OUTPUT_FILE=$(mktemp)
trap 'cleanup; rm -f "${OUTPUT_FILE}"' EXIT

rc=0
KUBE_TEST_ARGS="-run TestCorrectness -count=${COUNT} -v" \
    WHAT="${WHAT}" \
    make -C "${KUBE_ROOT}" test-integration 2>&1 | tee "${OUTPUT_FILE}" || rc=$?

cleanup

# A non-zero exit code is not sufficient evidence: a missing etcd or a compile
# error also fails the build. Require an actual test failure from the suite.
if ! grep -q -- "--- FAIL: TestCorrectness" "${OUTPUT_FILE}"; then
  if [[ "${rc}" -ne 0 ]]; then
    kube::log::error "Inconclusive: the build failed before TestCorrectness reported a result."
    kube::log::error "Fix the environment (etcd on PATH, working build) and retry."
    exit 1
  fi
  kube::log::error "NOT reproduced: the correctness suite passed with the fix for issue ${ISSUE} reverted."
  kube::log::error "Detection of this bug class has been lost."
  exit 1
fi

kube::log::status "Reproduced: issue ${ISSUE} was detected by the correctness suite"
exit 0
