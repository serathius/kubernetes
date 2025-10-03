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

source "$(dirname "${BASH_SOURCE[0]}")"/gke-internal-configure-helper.sh

echo "Testing installable scripts..."
# read by process-installables
KUBE_BIN="$(dirname "${BASH_SOURCE[0]}")"/installable
export KUBE_BIN

KUBE_HOME=$(mktemp -d)
echo "Testing empty RENDERED_INSTALLABLES"
process-installables
rm -rf "${KUBE_HOME}"
rm /tmp/processed-installables
echo "OK"

KUBE_HOME=$(mktemp -d)
RENDERED_INSTALLABLES='{}'
echo "Testing RENDERED_INSTALLABLES=${RENDERED_INSTALLABLES}"
process-installables
rm -rf "${KUBE_HOME}"
rm /tmp/processed-installables
echo "OK"

# Test installable-component-exists
RENDERED_INSTALLABLES='{"foo":{"bar":{"kind":"apppkg","apiVersion":"installable.gke.io/v1","metadata":{"name":"bar","creationTimestamp":null},"os":"OS","arch":"X86_64","version":"version","remoteURL":"remoteURL","digest":"digest","digestAlgo":"digestAlgo","installPrefix":"/install/prefix"}}}'
if installable-component-exists "bar"; then
  echo "Failed: installable-component-exists find the non-existent component bar"
fi
if ! installable-component-exists "foo"; then
  echo "Failed: installable-component-exists cannot find the existent component foo"
fi
