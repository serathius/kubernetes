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

# This worfklow runs integration tests on top of COS VMs. It is intended to run "installable"
# workflows as developers are migrating components to use installables in EVE.

set -o errexit
set -o nounset
set -o pipefail

# This is the family of COS image to use (e.g. cos-117-lts).
COS_FAMILY="${COS_FAMILY:-cos-stable}"
# The family to which the created images will belong.
OUTPUT_IMAGE_FAMILY="${OUTPUT_IMAGE_FAMILY:-installable-ci-images}"


root_dir=$(dirname "${BASH_SOURCE[0]}")/../..
pushd "${root_dir}"
REPO_ROOT="${REPO_ROOT:-$(pwd)}"
popd

pushd  "${REPO_ROOT}/gke/cluster/gce/gci/installable"
gcloud builds submit --config "${REPO_ROOT}/gke/hack/installable_cloudbuild.yaml" \
  --substitutions="_OUTPUT_IMAGE_FAMILY_=${OUTPUT_IMAGE_FAMILY}",_COS_FAMILY_="${COS_FAMILY}" .
popd

# Best effort to cleanup deprecated images from this family. This command returns images that are
# marked as deprecated with a delete time. The cloud_build workflow that runs the cos-customizer
# tool replaces old images in the same family (family arg above) with the newest image. It then
# marks the older images with a delete time.
# See: https://cos.googlesource.com/cos/tools/+/refs/heads/master/src/cmd/cos_customizer/
deleted_images=$(gcloud compute images list \
  --filter="family:${OUTPUT_IMAGE_FAMILY} AND deprecated.deleted > -P1D" \
  --show-deprecated --format="value(NAME)" --quiet)
readarray -t  images <<< "${deleted_images}"
for image in "${images[@]}"
do
    echo "deleting image: ${image}"
    gcloud compute images delete "${image}" --quiet || true
done