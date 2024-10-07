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

  systemctl daemon-reload
  systemctl enable gke-placeholder-resume-trigger.service


  # TODO: We hardcode the driver verision to latest temporarily.
  # Once we have the desired GPU driver version in the suspended state group, we will read it from GCE metadata and pass it to the --version.
  if lspci | grep -q -i NVIDIA; then
    local driver_version="latest"
    log "Pre-installing GPU driver ${driver_version}"

    # Note #1: --no-verify is to skip loading kernel modules. There is a bug of suspend/resume on GPU VMs if kernel modules are loaded.
    # During post-resume, the GPU device plugin will attempt to install the driver again.
    # The cos-gpu-installer will find the driver files are existed thus skipping downloading. And it will load kernel modules.
    cos-extensions install gpu -- --version="latest" --no-verify --host-dir /home/kubernetes/bin/nvidia
  else
    log "No GPU detected; skipping GPU driver install"
  fi

  log "Marking as ready to be suspended in MDS..."
  write_to_mds "$INIT_STATE_GUEST_ATTRIBUTE" "INITIALIZED"
  wait_for_suspension

  log "Continuing the placeholder bootstrapping after resume..."

  # b/365605093 - On resume, gve must be reloaded because mac address is changed on resume and must be refreshed
  log "Reloading gvnic"
  rmmod gve; modprobe gve

  log "Wait for systemd-networkd-wait-online..."
  systemctl restart systemd-networkd-wait-online.service

  log "Wait for gcr connectivity..."
  systemctl restart gcr-wait-online.service

  log "Restart google-guest-agent.service..."
  systemctl restart google-guest-agent.service

  log "Done with placeholders-presuspend.sh"
}

handle_placeholder_vm
