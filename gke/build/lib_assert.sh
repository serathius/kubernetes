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

set -o errexit
set -o nounset
set -o pipefail

__script_dir="$(dirname "$(realpath "$0")")"

# shellcheck source=./lib_log.sh
source "${__script_dir}"/lib_log.sh

assert_variable_equality()
{
  if [[ "${1}" != "${2}" ]]; then
    log.fail "assertion failure: \`${1}' is not equal to \`${2}'"
  fi
}

assert_variable_inequality()
{
  if [[ "${1}" == "${2}" ]]; then
    log.fail "assertion failure: \`${1}' is equal to \`${2}'"
  fi
}

assert_variable_not_empty()
{
  if [[ -z "${1}" ]]; then
    log.fail "assertion failure: variable \`${1}' cannot be empty"
  fi
}

assert_path_exists()
{
  if [[ ! -f "${1}" ]]; then
    log.fail "assertion failure: path \`${1}' does not exist"
  fi
}

assert_pathregex_exists_in_tar()
{
  local tarball="${1}"
  local pathregex="${2}"
  log.info "checking for ${pathregex} in ${tarball}"
  if ! tar tf "${tarball}" | grep "${pathregex}" >/dev/null 2>&1; then
    log.fail "could not detect ${pathregex} in ${tarball}"
  fi
}
