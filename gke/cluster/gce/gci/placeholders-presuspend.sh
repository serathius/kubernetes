#!/usr/bin/env bash

set -o nounset
set -o errexit
set -o pipefail

INIT_STATE_GUEST_ATTRIBUTE="guest-attributes/google-compute/initialization-state"

write_to_mds() {
  path="$1"
  data="$2"
  /usr/bin/curl --fail --retry 5 --retry-delay 3 --silent --show-error -X PUT --data "$data" "http://metadata.google.internal/computeMetadata/v1/instance/$path" -H "Metadata-Flavor: Google"
}

get_cluster_name() {
  echo $(/usr/bin/curl --fail --retry 5 --retry-delay 3 --silent --show-error -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/cluster-name" || true)
}

wait_for_suspension() {
  clusterName="$(get_cluster_name)"
  echo "Waiting for cluster-name metadata to be set"
  while [ "$clusterName" == "" ];
  do
    sleep 1
    clusterName="$(get_cluster_name)"
  done
  echo "Fetched cluster name: $clusterName"
}

handle_placeholder_vm() {
  echo "It is a Placeholder VM"
  write_to_mds "$INIT_STATE_GUEST_ATTRIBUTE" "INITIALIZING"

  # TODO: We hardcode the driver verision to latest temporarily.
  # Once we have the desired GPU driver version in the suspended state group, we will read it from GCE metdata and pass it to the --version.
  if lspci | grep -q -i NVIDIA; then
    local driver_version="latest"
    echo "Pre-installing GPU driver ${driver_version}"

    # Note #1: --no-verify is to skip loading kernel modules. There is a bug of suspend/resume on GPU VMs if kernel modules are loaded.
    # During post-resume, the GPU device plugin will attempt to install the driver again.
    # The cos-gpu-installer will find the driver files are existed thus skipping downloading. And it will load kernel modules.
    cos-extensions install gpu -- --version="latest" --no-verify --host-dir /home/kubernetes/bin/nvidia
  else
    echo "Nothing to be done"
  fi

  # If there is any error above, the whole script will be aborted and then suspestion won't happen.
  # GCE SuspendStates service will timeout and fail the process of generating suspended states.

  echo "Marking as ready to be suspended..."
  write_to_mds "$INIT_STATE_GUEST_ATTRIBUTE" "INITIALIZED"
  wait_for_suspension
  echo "Continuing the bootstrapping..."
}

handle_placeholder_vm