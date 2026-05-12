#!/usr/bin/env bash

# Copyright Google
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

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# lint gke source files first
"${REPO_ROOT}/gke/hack/verify-boilerplate.py"

# setup worktree so we can temporarily alter the repo
tmpdir="$(mktemp -d -t "verify-boilerplate-gke.XXXXXX")"
git worktree add -f -q "${tmpdir}" HEAD
trap 'git worktree remove -f "${tmpdir:?}"; rm -rf "${tmpdir:?}"' EXIT
cd "${tmpdir:?}" || exit
# remove gke-internal files before running upstream linter
rm -rf ./gke/
hack/verify-boilerplate.sh
