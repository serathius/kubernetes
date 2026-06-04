#!/usr/bin/env bash

# Copyright 2024 Google
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

set -o nounset
set -o errexit
set -o pipefail

# Directory for predownloaded NVIDIA driver versions.
readonly NVIDIA_PRELOAD_DIR="/home/kubernetes/bin/nvidia-preload"

INIT_STATE_GUEST_ATTRIBUTE="guest-attributes/google-compute/initialization-state"

# Global variable set from node label metadata.
GPU_DRIVER_VERSION=""

write_to_mds() {
  path="$1"
  data="$2"
  /usr/bin/curl --fail --retry 5 --retry-delay 3 --silent --show-error -X PUT --data "$data" "http://metadata.google.internal/computeMetadata/v1/instance/$path" -H "Metadata-Flavor: Google"
}

log() {
  # Get current time.
  local current_time
  current_time="$(date --utc '+%s.%N')"
  # ...formatted as UTC RFC 3339.
  local timestamp
  timestamp="$(date --utc --date="@${current_time}" '+%FT%T.%NZ')"

  msg="$1"
  echo "placeholders-presuspend.sh ${timestamp} ${msg}"
}

wait_for_suspension() {
  log "Waiting for resume"
  while ! systemctl is-active --quiet gke-placeholder-resume-trigger.service; do
    sleep "0.2"
    log "Waiting for gke-placeholder-resume-trigger..."
  done
}

# Retrieves the GPU driver version from instance metadata and sets the global variable
# "GPU_DRIVER_VERSION".
get_gpu_driver_version_from_metadata() {
  LABELS=$(curl --retry 5 -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-labels || {
    log "ERROR: Failed to retrieve metadata."
    return 1
  })

  local original_ifs="$IFS"
  IFS=,; for label in $LABELS; do
    IFS='='; read -r LABEL VALUE <<< "$label"
    if [[ "${LABEL}" == "cloud.google.com/gke-gpu-driver-version" ]]; then
      log "Found GPU driver version: $VALUE"
      GPU_DRIVER_VERSION=$VALUE
      return 0
    fi
  done
  IFS="$original_ifs"

  log "GPU driver version label not found."
  return 1
}

# Mounts the specified pre-downloaded NVIDIA driver ("latest" or "default") based on the
# retrieved node label metadata. This function assumes both driver versions have already been downloaded.
# It performs the bind mount and cleans up the unused driver.
mount_nvidia_driver() {
  # The node has just been resumed, this means no bootstrapping has run yet, and
  # /home/kubernetes/bin/nvidia does not exist to perform the bind mount on.
  # Create the directory because it doesn't exist.
  local mount_point="/home/kubernetes/bin/nvidia"
  mkdir -p "${mount_point}"

  # These variables define the directories where the pre-downloaded NVIDIA drivers are stored.
  local -r preloaded_gpu_driver_dir_latest="${NVIDIA_PRELOAD_DIR}/latest"
  local -r preloaded_gpu_driver_dir_default="${NVIDIA_PRELOAD_DIR}/default"

  # Proceed with bind mounting
  if [[ "${GPU_DRIVER_VERSION}" == "latest" && -d "$preloaded_gpu_driver_dir_latest" ]]; then
    log "Bind mounting latest NVIDIA driver: $preloaded_gpu_driver_dir_latest to $mount_point"
    mount --bind "$preloaded_gpu_driver_dir_latest" "$mount_point"

    log "Deleting unused driver version: default."
    # 7 is the lowest priority for systemd-run(ref: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).
    systemd-run --no-block --property=IOSchedulingPriority=7 rm -rf "$preloaded_gpu_driver_dir_default"
  elif [[ "${GPU_DRIVER_VERSION}" == "default" && -d "$preloaded_gpu_driver_dir_default" ]]; then
    log "Bind mounting default NVIDIA driver: $preloaded_gpu_driver_dir_default to $mount_point"
    mount --bind "$preloaded_gpu_driver_dir_default" "$mount_point"

    log "Deleting unused driver version: latest."
    # 7 is the lowest priority for systemd-run(ref: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).
    systemd-run --no-block --property=IOSchedulingPriority=7 rm -rf "$preloaded_gpu_driver_dir_latest"
  else
    log "ERROR: Invalid BoltVMs GPU_DRIVER_VERSION: $GPU_DRIVER_VERSION. Deleting pre-downloaded driver modules due to invalid version."
    # Clean up both preloaded drivers since neither seem to be valid and are consuming disk space.
    systemd-run --no-block --property=IOSchedulingPriority=7 rm -rf "$preloaded_gpu_driver_dir_latest" "$preloaded_gpu_driver_dir_default"
    return 1
  fi

  return 0
}

handle_placeholder_vm() {
  log "Starting placeholders-presuspend.sh"

  if curl --fail --retry 5 --retry-delay 3 --silent --output /dev/null -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/cluster-name"; then
    log "cluster-name is already set; exiting placeholders-presuspend.sh"
    return 0
  fi

  log "Marking as initailizing in MDS..."
  write_to_mds "$INIT_STATE_GUEST_ATTRIBUTE" "INITIALIZING"

  cat <<EOF >/etc/systemd/system/gke-placeholder-resume-trigger.service
[Unit]
Description=GKE Placeholder Resume Trigger
After=suspend.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/true

[Install]
WantedBy=suspend.target
EOF

  # Prior the VM suspending; we unload gvnic module as part of b/365605093 and b/374160698. It is reloaded after the VM has resumed.
  cat <<EOF >/etc/systemd/system/gke-placeholder-suspend-trigger.service
[Unit]
Description=GKE Placeholder Suspend Trigger
Before=sleep.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/rmmod gve

[Install]
WantedBy=sleep.target
EOF

  systemctl daemon-reload
  systemctl enable gke-placeholder-resume-trigger.service gke-placeholder-suspend-trigger.service


  # Ensure this is a node with GPUs before preloading both LATEST & DEFAULT driver versions.
  if lspci | grep -q -i NVIDIA; then

    # Note: --no-verify is to skip loading kernel modules. There is a bug of suspend/resume on GPU VMs if kernel modules are loaded.
    # During post-resume, the GPU device plugin will attempt to install the driver again.
    # The cos-gpu-installer will find the driver files are existed thus skipping downloading. And it will load kernel modules.
    cos-extensions install gpu -- --version="latest" --no-verify --host-dir "${NVIDIA_PRELOAD_DIR}/latest"
    cos-extensions install gpu -- --version="default" --no-verify --host-dir "${NVIDIA_PRELOAD_DIR}/default"
  else
    log "No GPU detected; skipping GPU driver install"
  fi

  log "Marking as ready to be suspended in MDS..."
  write_to_mds "$INIT_STATE_GUEST_ATTRIBUTE" "INITIALIZED"
  wait_for_suspension

  log "Continuing the placeholder bootstrapping after resume..."

  # b/365605093 - On resume, gve must be reloaded because mac address is changed on resume and must be refreshed
  log "Reloading gvnic"
  modprobe gve

  # 1. Re-run the resize-stateful-partition.service to ensure that the stateful
  # partition is properly resized
  # 2. Re-run the systemd-networkd-wait-online.service to ensure network is
  # properly configured after resume. See b/365605093.
  # 3. Re-run the gcr-wait-online.service to ensure the connectivity is
  # established.
  # 4. Re-run the google-guest-agent.service to ensure that the guest agent is
  # configured with the correct VM metadata.
  # 5. Re-run the google-osconfig-agent.service to ensure that the osconfig
  # agent is configured with the correct VM metadata.
  log "Restarting services..."
  # Restart the services in parallel to speed up the process.
  systemctl restart resize-stateful-partition.service \
    systemd-networkd-wait-online.service \
    gcr-wait-online.service

  systemctl restart --no-block \
    google-guest-agent.service \
    google-osconfig-agent.service || true

  # Ensure this is a node with GPUs before querying GPU version from node label &
  # conducting mount binding to /bin/nvidia
  if lspci | grep -q -i NVIDIA; then
    log "NVIDIA GPU detected."
    if ! get_gpu_driver_version_from_metadata; then
      log "WARNING: Failed to get GPU driver version from metadata. Skipping mount_nvidia_driver."
    else
      if ! mount_nvidia_driver; then
        log "WARNING: Failed to mount NVIDIA driver. Continuing without mounting preloaded driver."
      fi
    fi
  else
    log "No NVIDIA GPU detected. Skipping GPU-related operations."
  fi

  log "Done with placeholders-presuspend.sh"
}

handle_placeholder_vm
