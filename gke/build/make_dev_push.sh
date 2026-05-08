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

# Like make_dev_simple.sh, but pushes to GCS.
#
# Note that license and source injection steps are still skipped. If you want to
# enable them, just pass in "SKIP_DOCKER_LICENSE_INJECTION=0" and
# "SKIP_DOCKER_SOURCE_INJECTION=0" as arguments to this script.

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(dirname "$(realpath "$0")")"

"${SCRIPT_DIR}"/make_custom.sh \
  GKE_BUILD_ACTIONS=compile,package,validate,push-gcs \
  GKE_BUILD_CONFIG="${SCRIPT_DIR}/config/common.yaml,${SCRIPT_DIR}/config/dev_simple.yaml" \
  SKIP_DOCKER_LICENSE_INJECTION=1 \
  SKIP_DOCKER_SOURCE_INJECTION=1 \
  VERSION_SUFFIX="${USER}" \
  INJECT_DEV_VERSION_MARKER=1 \
  "$@"
