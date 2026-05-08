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

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
# shellcheck source=./lib_gke.sh
source "${SCRIPT_DIR}"/lib_gke.sh

# Hook to run before invoking from a louhi_prod.sh (or other scripts that are
# meant for execution from inside Louhi).
louhi_hook()
{
  log.debugvar _LOUHI_BRANCH_NAME

  # Louhi puts us in a detached HEAD state. This is not a problem, but for the
  # sake of having as few unnecessary differences as possible among the
  # different build environments, we checkout the branch name from HEAD.
  #
  # The -f flag is needed to force this operation to succeed even if there is a
  # branch (default branch, such as "master") that already exists and matches
  # _LOUHI_BRANCH_NAME.
  git branch -f "${_LOUHI_BRANCH_NAME}" HEAD
  git checkout -f "${_LOUHI_BRANCH_NAME}"

  branch_hook "${_LOUHI_BRANCH_NAME}"

  # shellcheck disable=SC2034
  __GKE_BUILD_ACTIONS=compile,package,validate,push-gcs,push-gcr
}
