#!/usr/bin/env bash

# Copyright 2026 Google
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

# script to print a GOTOOLCHAIN version based on build/config
set -o errexit -o nounset -o pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}"/../.. && pwd -P)"

# shellcheck source=./lib_gke.sh
source "${SCRIPT_DIR}"/lib_gke.sh

# read from config
__GKE_BUILD_CONFIG="${SCRIPT_DIR}/config/common.yaml"
__golang_image=$(get_val 'build-env.compiler-image.deps.golang-image' 2>/dev/null)

# parse, which sets golang_tag
set_compiler_image_tag

# get .go-version from OSS
oss_go_version=$(head -n1 "${REPO_ROOT}/.go-version")

# select the latest version
# sort -V handles major, minor, patch, and pre-release which should be sufficient
latest_version=$(echo -e "${golang_tag:?}\n${oss_go_version}\n" | sort -V | tail -n1)

# output GOTOOLCHAIN compatible value
echo "go${latest_version}"
