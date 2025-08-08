#!/usr/bin/env bash
# This script tags preloaded AR release and prod images from the statically tagged source
# region (us-central1) to the VM region.

set -o nounset
set -o errexit
set -o pipefail

# Set the maximum number of concurrent 'ctr' commands to run. This value is a
# safe upper limit to avoid unknowingly overwhelming the system.
MAX_JOBS=30
SOURCE_REGION=us-central1

tag_image() {
  local image=$1

  local new_image=${image//${SOURCE_REGION}/${DEST_REGION}}

  echo "Tagging image ${image} to ${new_image}"
  ctr -n k8s.io images tag "${image}" "${new_image}";
}

tag_preloaded_images() {
  # The KUBE_DOCKER_REGISTRY variable is expected to be in the environment
  if [[ -z "${KUBE_DOCKER_REGISTRY:-}" ]]; then
    echo "KUBE_DOCKER_REGISTRY environment variable is not set" >&2
    exit 1
  fi

  DEST_REGION=$(echo "${KUBE_DOCKER_REGISTRY}" | cut -d'-' -f1-2)

  if [[ "${SOURCE_REGION}" == "${DEST_REGION}" ]]; then
      echo "Preloaded region (${SOURCE_REGION}) is the same as the current region. No retagging needed."
      exit 0
  fi

  export DEST_REGION
  export SOURCE_REGION
  export -f tag_image

  images_to_tag=$(ctr -n k8s.io images list -q | grep -E "${SOURCE_REGION}-artifactregistry.gcr.io/gke-release-staging/gke-release-staging|${SOURCE_REGION}-artifactregistry.gcr.io/gke-release/gke-release" || true)
  if [[ -z "${images_to_tag}" ]]; then
    echo "No preloaded images from ${SOURCE_REGION} found to retag."
    exit 0
  fi

   echo "${images_to_tag}" | xargs -P "${MAX_JOBS}" -I {} bash -c 'tag_image "{}"'
}

tag_preloaded_images
