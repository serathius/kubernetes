#!/usr/bin/env bash

# Copyright 2020 Google
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

# This script wraps around the make_louhi_{ci,prod}.sh entrypoints and chooses
# either one based on the branch name.

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(dirname "$(realpath "$0")")"

# If explicitly requested, trigger a release build
if [[ "${_FORCE_RELEASE_BUILD:-}" == "true" ]]; then
  "${SCRIPT_DIR}"/make_louhi_prod.sh
  exit 0
fi

# Otherwise, auto-detect release build branches
case "${_LOUHI_BRANCH_NAME}" in
  release-*-gke.* | release-*-*.*-frontier)  # e.g., release-1.35.1-gke.1 or release-1.35.1-megawhale.1-frontier
    "${SCRIPT_DIR}"/make_louhi_prod.sh
  ;;
  *)
    "${SCRIPT_DIR}"/make_louhi_ci.sh
  ;;
esac
