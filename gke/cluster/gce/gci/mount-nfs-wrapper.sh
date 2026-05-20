#!/usr/bin/env bash

# Copyright 2026 The Kubernetes Authors.
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

# A host-level mount.nfs wrapper that executes inside a private mount namespace
# with KubeDNS to allow in-cluster Kubernetes Service DNS resolution.

# We intentionally do NOT hardcode or override the system PATH here (e.g., export PATH="...").
# Doing so overrides Kubelet's native execution environment path and is fragile across GKE
# OS image updates (COS, Ubuntu, etc.) which may shift helper binaries to custom systemd
# directories. Instead, the wrapper dynamically inherits the standard host environment PATH.
KUBELET_CONFIG="/home/kubernetes/kubelet-config.yaml"
LOG_FILE="/var/log/mount-nfs-wrapper.log"

log_info() {
  local -r msg="$1"
  echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $msg" >> "$LOG_FILE" 2>/dev/null || true
  logger -t mount.nfs-wrapper "[INFO] $msg" || true
}

log_error() {
  local -r msg="$1"
  echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $msg" >> "$LOG_FILE" 2>/dev/null || true
  logger -t mount.nfs-wrapper "[ERROR] $msg" || true
}

log_info "mount.nfs intercepted with arguments: $*"

# Ensure rpcbind is running on the host to support NFS lock manager (NLM) for NFS v3 mounts.
# Note: If rpcbind fails to start, it is logged as an error but we intentionally do NOT
# exit or fail the mount execution. This allows NFS v4 mounts (which do not require rpcbind
# or locking port coordination) to continue working perfectly. If the mount actually
# needs rpcbind (NFS v3) and rpcbind is not running, mount.nfs.real will fail cleanly.
if ! systemctl is-active --quiet rpcbind; then
  log_info "rpcbind is inactive, attempting to start it..."
  systemctl start rpcbind || log_error "failed to start rpcbind (this is non-fatal and safe to ignore if mounting NFSv4)"
fi

# Extract Cluster DNS IP from Kubelet Configuration
CLUSTER_DNS=$(awk '/clusterDNS:/{flag=1;next}/^[a-zA-Z]/{flag=0}flag{print}' "$KUBELET_CONFIG" | grep "-" | sed 's/- //' | head -n 1 | tr -d '[:space:]')
log_info "Extracted CLUSTER_DNS: '$CLUSTER_DNS'"

if [[ -n "$CLUSTER_DNS" ]]; then
  SEARCH_DOMAINS=$(grep "search" /etc/resolv.conf)
  log_info "Extracted host SEARCH_DOMAINS: '$SEARCH_DOMAINS'"

  # Prepare temporary DNS settings
  TMP_RESOLV=$(mktemp /tmp/resolv.XXXXXX)
  echo -e "nameserver $CLUSTER_DNS\n$SEARCH_DOMAINS" > "$TMP_RESOLV"
  chmod 644 "$TMP_RESOLV"
  log_info "Created temporary resolv.conf at $TMP_RESOLV"

  RESOLV_TARGET=$(readlink -f /etc/resolv.conf)
  RESOLV_DIR=$(dirname "$RESOLV_TARGET")
  log_info "Resolved target resolv.conf path: $RESOLV_TARGET (parent: $RESOLV_DIR)"

  # Run real mount.nfs inside a private mount namespace with custom resolv.conf.
  # We use --propagation shared so NFS mounts propagate back to the host.
  # We self-bind-mount /etc and make it private to isolate custom resolv.conf from the host.
  # We pass variables as positional parameters to sh -c to avoid shell quoting and escaping hazards.
  if unshare --mount --propagation shared -- true &>/dev/null; then
    log_info "Entering private mount namespace with propagation shared..."
    # shellcheck disable=SC2016
    exec unshare --mount --propagation shared -- bash -c '
      RESOLV_DIR="$1"
      TMP_RESOLV="$2"
      RESOLV_TARGET="$3"
      shift 3

      cleanup() {
        rm -f "$TMP_RESOLV"
      }
      trap cleanup EXIT INT TERM

      mount --bind /etc /etc || { logger -t mount.nfs-wrapper "[ERROR] failed to bind mount /etc"; exit 1; }
      mount --make-private /etc || { logger -t mount.nfs-wrapper "[ERROR] failed to make /etc private"; exit 1; }

      if [[ -d "$RESOLV_DIR" ]]; then
        mount --bind "$RESOLV_DIR" "$RESOLV_DIR" || { logger -t mount.nfs-wrapper "[ERROR] failed to bind mount $RESOLV_DIR"; exit 1; }
        mount --make-private "$RESOLV_DIR" || { logger -t mount.nfs-wrapper "[ERROR] failed to make $RESOLV_DIR private"; exit 1; }
      fi

      mount --bind "$TMP_RESOLV" "$RESOLV_TARGET" || { logger -t mount.nfs-wrapper "[ERROR] failed to bind custom resolv.conf"; exit 1; }

      cleanup
      trap - EXIT INT TERM

      logger -t mount.nfs-wrapper "[INFO] Executing real mount.nfs in private namespace..."
      exec /home/kubernetes/bin/mount.nfs.real "$@"
    ' -- "$RESOLV_DIR" "$TMP_RESOLV" "$RESOLV_TARGET" "$@"
  else
    log_error "unshare --mount --propagation shared is not supported. Falling back to host namespace execution."
    rm -f "$TMP_RESOLV"
    exec /home/kubernetes/bin/mount.nfs.real "$@"
  fi
else
  log_info "No CLUSTER_DNS found. Executing real mount.nfs in host namespace..."
  exec /home/kubernetes/bin/mount.nfs.real "$@"
fi
