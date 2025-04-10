#!/bin/bash

# Copyright 2024 The Kubernetes Authors.
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


python3 installable/installable_test.py -v

python3 installable/installable_e2e_test.py -v

source "$(dirname $0)/gke-internal-configure-helper.sh"

echo "Testing installable scripts..."
KUBE_BIN="$(dirname $0)/installable"

KUBE_HOME=$(mktemp -d)
echo "Testing empty RENDERED_INSTALLABLES"
process-installables
rm -rf $KUBE_HOME
echo "OK"

KUBE_HOME=$(mktemp -d)
readonly RENDERED_INSTALLABLES='{}'
echo "Testing RENDERED_INSTALLABLES=${RENDERED_INSTALLABLES}"
process-installables
rm -rf $KUBE_HOME
echo "OK"
