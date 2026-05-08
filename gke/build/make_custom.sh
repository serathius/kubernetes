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

# Build GKE. This is just a thin wrapper around lib.sh. Among the other
# ./make_*.sh scripts, this is the only one that assumes nothing about the
# build. That is, this script is the entrypoint where you have the most control.
# It's a blank slate for customizations!

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
# shellcheck source=./lib_gke.sh
source "${SCRIPT_DIR}"/lib_gke.sh

# We pass along any additional arguments specified in the command line over to
# the function, so that users can tweak the settings (esp. things like setting
# GKE_BUILD_CONFIG and GKE_BUILD_ACTIONS).
gke_build_entrypoint "$@"
