#!/bin/bash

function start_internal_cluster_autoscaler {
  if [[ "${GKE_CLUSTER_AUTOSCALER_ON_CRP:-}" == "true" ]]; then
    echo "Cluster Autoscaler will be deployed by CRP, nothing to do here."
    return
  fi

  if [[ "${ENABLE_NAP:-}" == "true" ]]; then
    echo "Start Node Auto-Provisioning (NAP)"
    start_internal_ca "${NAP_CONFIG:-} --node-autoprovisioning-enabled=true"
  elif [[ "${ENABLE_GKE_CLUSTER_AUTOSCALER:-}" == "true" ]]; then
    echo "Start Cluster Autoscaler from closed source"
    start_internal_ca "${GKE_CLUSTER_AUTOSCALER_CONFIG:-}"
  else
    echo "Not using closed source Cluster Autoscaler"
  fi
}

function start_internal_ca {
  local -r manifests_dir="${KUBE_HOME}/kube-manifests/kubernetes/gci-trusty"

  # Re-using Cluster Autoscaler setup functions from OSS
  setup-addon-manifests "addons" "rbac/cluster-autoscaler"
  create-kubeconfig "cluster-autoscaler" ${KUBE_CLUSTER_AUTOSCALER_TOKEN}

  # Add our GKE specific CRD
  mkdir -p "${manifests_dir}/autoscaling"
  cp "${manifests_dir}/internal-capacity-request-crd.yaml" "${manifests_dir}/autoscaling"
  setup-addon-manifests "addons" "autoscaling"

  # Prepare Autoscaler manifest
  local -r src_file="${manifests_dir}/internal-cluster-autoscaler.manifest"
  local params="${CLOUD_CONFIG_OPT} $1"

  # split the params into separate arguments passed to binary
  local params_split
  params_split=$(eval "for param in $params; do echo -n \\\"\$param\\\",; done")
  params_split=${params_split%?}

  sed -i -e "s@{{params}}@${params_split:-}@g" "${src_file}"
  sed -i -e "s@{{cloud_config_mount}}@${CLOUD_CONFIG_MOUNT}@g" "${src_file}"
  sed -i -e "s@{{cloud_config_volume}}@${CLOUD_CONFIG_VOLUME}@g" "${src_file}"
  sed -i -e "s@{%.*%}@@g" "${src_file}"

  cp "${src_file}" /etc/kubernetes/manifests
}

function add_vpa_admission_webhook_host {
  original_ipv6_loopback_line=`grep "^::1[[:space:]]" /etc/hosts`
  tmp_file=`mktemp`
  grep -v "^::1[[:space:]]" /etc/hosts >${tmp_file}
  cat ${tmp_file} >/etc/hosts
  if [[ -n "${original_ipv6_loopback_line:-}" ]]; then
    echo "${original_ipv6_loopback_line} vpa.admissionwebhook.localhost" >>/etc/hosts
  else
    echo "::1 vpa.admissionwebhook.localhost" >>/etc/hosts
  fi
}

function start_pod_autoscaler {
  local -r manifests_dir="${KUBE_HOME}/kube-manifests/kubernetes/gci-trusty"
  mkdir -p "${manifests_dir}/pod-autoscaler"
  if [[ "${ENABLE_VERTICAL_POD_AUTOSCALER:-}" == "true" ]]; then
    echo "Start Vertical Pod Autoscaler (VPA)"
    generate_vertical_pod_autoscaler_admission_controller_certs
    add_vpa_admission_webhook_host

    cp "${manifests_dir}/internal-vpa-crd.yaml" "${manifests_dir}/pod-autoscaler"
    cp "${manifests_dir}/internal-vpa-rbac.yaml" "${manifests_dir}/pod-autoscaler"
    if [[ "${ENABLE_MULTIDIM_POD_AUTOSCALER:-}" == "true" ]]; then
      cp "${manifests_dir}/internal-mpa-crd.yaml" "${manifests_dir}/pod-autoscaler"
      cp "${manifests_dir}/internal-mpa-rbac.yaml" "${manifests_dir}/pod-autoscaler"
    fi
    setup-addon-manifests "addons" "pod-autoscaler"

    for component in admission-controller recommender updater; do
      setup_pod_autoscaler_component ${component} ${manifests_dir}
    done
  elif [[ "${ENABLE_UNIFIED_AUTOSCALING:-}" == "true" ]]; then
    cp "${manifests_dir}/internal-kuba-rbac.yaml" "${manifests_dir}/pod-autoscaler"
    setup-addon-manifests "addons" "pod-autoscaler"

    echo "Start Kubernetes Adapter for Unified Autoscaler (KUBA)"
    setup_pod_autoscaler_component "recommender" ${manifests_dir}
  fi
}

function base64_decode_or_die {
  local variable_name=$1
  local out_file=$2
  if [[ -n "${!variable_name}" ]]; then
    if ! base64 -d - <<<${!variable_name} >${out_file}; then
      echo "==error base 64 decoding ${variable_name}=="
      echo "==the value of the variable is ${!variable_name}=="
      exit 1
    fi
  else
    echo "==VPA enabled but ${variable_name} is not set=="
    exit 1
  fi
}

function setup_pod_autoscaler_component {
  local component=$1
  local manifests_dir=$2
  create-static-auth-kubeconfig-for-component vpa-${component}

  # Prepare manifest
  local src_file="${manifests_dir}/internal-vpa-${component}.manifest"

  if [[ ${component} == "recommender" ]]; then
    local uas_params="${UAS_PARAMS:-}"
    # split the params into separate arguments passed to binary
    local uas_params_split
    uas_params_split=$(eval "for param in $uas_params; do echo -n ,\\\"\$param\\\"; done")
    sed -i -e "s@{{uas_params}}@${uas_params_split:-}@g" "${src_file}"

    # set memory limit for vpa-recommender. Limit default value
    # justification in http://b/163760835#comment8
    local memory_limit="${POD_AUTOSCALER_MEMORY_LIMIT:-4Gi}"
    sed -i -e "s@{{memory_limit}}@${memory_limit}@g" "${src_file}"
  fi

  sed -i -e "s@{{cloud_config_mount}}@${CLOUD_CONFIG_MOUNT}@g" "${src_file}"
  sed -i -e "s@{{cloud_config_volume}}@${CLOUD_CONFIG_VOLUME}@g" "${src_file}"
  sed -i -e "s@{%.*%}@@g" "${src_file}"

  cp "${src_file}" /etc/kubernetes/manifests
}

function generate_vertical_pod_autoscaler_admission_controller_certs {
  local certs_dir="/etc/tls-certs" #TODO: what is the best place for certs?
  echo "Generating certs for the VPA Admission Controller in ${certs_dir}."
  mkdir -p ${certs_dir}
  if [[ -n "${CA_CERT:-}" ]] && [[ -n "${VPA_AC_KEY:-}" ]] && [[ -n "${VPA_AC_CERT:-}" ]]; then
    base64_decode_or_die "CA_CERT" ${certs_dir}/caCert.pem
    base64_decode_or_die "VPA_AC_KEY" ${certs_dir}/serverKey.pem
    base64_decode_or_die "VPA_AC_CERT" ${certs_dir}/serverCert.pem
  else
    echo "==At least one of CA_CERT, VPA_AC_KEY, VPA_AC_CERT is missing=="
    exit 1
  fi
}

function create-static-auth-kubeconfig-for-component {
  local component=$1
  echo "Creating token for component ${component}"
  local token="$(secure_random 32)"
  append_or_replace_prefixed_line /etc/srv/kubernetes/known_tokens.csv "${token}," "system:${component},uid:system:${component}"
  create-kubeconfig ${component} ${token}
}

function gke-internal-master-start {
  echo "Internal GKE configuration start"
  compute-master-manifest-variables
  start_internal_cluster_autoscaler
  start_pod_autoscaler
  echo "Internal GKE configuration done"
}

# Configure the node kernel parameters.
#
# This function expects no arguments.
#
# This function
#   - Reads the kernel parameter default values from release artifacts and the
#     overrides from SYSCTL_OVERRIDES, generates the sysctl conf files under
#     /etc/sysctl.d/, and applies them using systemd-sysctl.
#   - Sets the variable POD_SYSCTLS with the namespaced GKE fleetwide kernel
#     parameters and the user overrides. The variable is expected to be read
#     by the start-kubelet function.
function configure-node-sysctls {
  local -r dir="${KUBE_HOME}/kube-manifests/kubernetes/gci-trusty/sysctl"
  # sysctl_overrides - list of sysctls supplied from GKE control plane to
  # override default sysctls for host namespace (supplied by user).
  local -r sysctl_overrides="${SYSCTL_OVERRIDES:-}"
  # pod_sysctl_overrides - list of sysctls supplied from GKE control plane to
  # override default sysctls in pod namespaces. Note that sysctl_overrides
  # will take precedence over this.
  local -r pod_sysctl_overrides="${EXTRA_POD_SYSCTLS:-}"
  local -r namespaced_sysctl_names="${dir}/namespaced-sysctl-names.yaml"
  # Use the GKE fleetwide default values if ENABLE_SYSCTL_TUNING is "true".
  if [[ "${ENABLE_SYSCTL_TUNING:-}" == "true" ]]; then
    local -r sysctl_defaults="${dir}/sysctl-defaults.yaml"
  else
    local -r sysctl_defaults="/dev/null"
  fi

  local -r conf_dir="/etc/sysctl.d"
  # The overrides must be applied after the defaults. This is guaranteed by
  # the alphabetical order of the file names.
  #
  # It's guaranteed that 99-sysctl.conf is the only file that comes after
  # 99-gke-defaults.conf and 99-gke-overrides.conf in the current sysctl config
  # layout on COS and Ubuntu.
  #
  # On both images, 99-sysctl.conf is a symlink to /etc/sysctl.conf, which
  # contains no settings.
  #
  # TODO(b/131158180): Allow GKE to provide sysctl config files in a more
  # reliable way by renaming the existing 99-*.conf files to 8x-*.conf.
  local -r output_defaults="${conf_dir}/99-gke-defaults.conf"
  local -r output_overrides="${conf_dir}/99-gke-overrides.conf"

  # Create the directory in case it doesn't exist.
  mkdir -p "${conf_dir}"

  echo "Sysctl overrides: ${sysctl_overrides}"

  # Generate the kernel parameter defaults and overrides configs in
  # /etc/sysctl.d/. They will be loaded by systemd-sysctl on reboot.
  python3 "${dir}/generate-conf-files.py" \
    --sysctl-defaults="${sysctl_defaults}" \
    --sysctl-overrides="${sysctl_overrides}" \
    --output-defaults=${output_defaults} \
    --output-overrides=${output_overrides}

  echo "Pod sysctl overrides: ${pod_sysctl_overrides}"

  # Extract the namespaced kernel parameter defaults and overrides that should
  # be passed to kubelet and set inside pod namespaces.
  POD_SYSCTLS=$(python3 "${dir}/extract-namespaced.py" \
    --sysctl-defaults="${sysctl_defaults}" \
    --sysctl-overrides="${sysctl_overrides}" \
    --pod-sysctl-overrides="${pod_sysctl_overrides}" \
    --namespaced-sysctl-names="${namespaced_sysctl_names}")

  echo "Sysctls to be set in pod namespaces: ${POD_SYSCTLS}"

  # Run systemd-sysctl to apply the kernel parameters on node.
  if [[ -e "/usr/lib/systemd/systemd-sysctl" ]]; then
    /usr/lib/systemd/systemd-sysctl
  else
    /lib/systemd/systemd-sysctl
  fi
}

function detect_mtu {
  local MTU=1460
  if [[ "${DETECT_MTU:-}" == "true" ]];then
    local default_nic=$(ip route get 8.8.8.8 | sed -nr "s/.*dev ([^\ ]+).*/\1/p")
    if [ -f "/sys/class/net/$default_nic/mtu" ]; then
      MTU=$(cat /sys/class/net/$default_nic/mtu)
    fi
  fi
  echo $MTU

}

function _gke_cni_template {
  local MTU="$(detect_mtu)"
  cat <<EOF
{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "ptp",
      "mtu": ${MTU},
      "ipam": {
        "type": "host-local",
        "subnet": "{{.PodCIDR}}",
        "routes": [
          {
            "dst": "0.0.0.0/0"
          }
        ]
      }
    },
    {
      "type": "portmap",
      "capabilities": {
        "portMappings": true
      }
    }
  ]
}
EOF
}

function gke-setup-containerd {
  local -r CONTAINERD_HOME="/home/containerd"
  mkdir -p "${CONTAINERD_HOME}"

  echo "Generating containerd config"
  local -r config_path="${CONTAINERD_CONFIG_PATH:-"/etc/containerd/config.toml"}"
  mkdir -p "$(dirname "${config_path}")"
  local cni_template_path="${CONTAINERD_HOME}/cni.template"
  _gke_cni_template > "${cni_template_path}"
  if [[ "${KUBERNETES_MASTER:-}" != "true" ]]; then
    if [[ "${NETWORK_POLICY_PROVIDER:-"none"}" != "none" || "${ENABLE_NETD:-}" == "true" ]]; then
      # Use Kubernetes cni daemonset on node if network policy provider is specified
      # or netd is enabled.
      cni_template_path=""
    fi
  fi
  # Use systemd cgroup driver when running on cgroupv2
  local systemdCgroup="false"
  if [[ "${CGROUP_CONFIG-}" == "cgroup2fs" ]]; then
    systemdCgroup="true"
  fi
  # Reuse docker group for containerd.
  local -r containerd_gid="$(cat /etc/group | grep ^docker: | cut -d: -f 3)"
  cat > "${config_path}" <<EOF
version = 2
required_plugins = ["io.containerd.grpc.v1.cri"]
# Kubernetes doesn't use containerd restart manager.
disabled_plugins = ["io.containerd.internal.v1.restart"]
oom_score = -999

[debug]
  level = "${CONTAINERD_LOG_LEVEL:-"info"}"

[grpc]
  gid = ${containerd_gid}

[plugins."io.containerd.grpc.v1.cri"]
  stream_server_address = "127.0.0.1"
  max_container_log_line_size = ${CONTAINERD_MAX_CONTAINER_LOG_LINE:-262144}
[plugins."io.containerd.grpc.v1.cri".cni]
  bin_dir = "${KUBE_HOME}/bin"
  conf_dir = "/etc/cni/net.d"
  conf_template = "${cni_template_path}"
[plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]
  endpoint = ["https://mirror.gcr.io","https://registry-1.docker.io"]
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
  SystemdCgroup = ${systemdCgroup}
EOF

  if [[ "${ENABLE_GCFS:-}" == "true" ]]; then
    gke-setup-gcfs
    cat >> "${config_path}" <<EOF
[plugins."io.containerd.grpc.v1.cri".containerd]
  default_runtime_name = "runc"
  snapshotter = "gcfs"
  disable_snapshot_annotations = false
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"
[proxy_plugins]
  [proxy_plugins.gcfs]
    type = "snapshot"
    address = "/run/containerd-gcfs-grpc/containerd-gcfs-grpc.sock"
EOF
  else
  cat >> "${config_path}" <<EOF
[plugins."io.containerd.grpc.v1.cri".containerd]
  default_runtime_name = "runc"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"
EOF
  fi

  local -r sandbox_root="${CONTAINERD_SANDBOX_RUNTIME_ROOT:-"/run/containerd/runsc"}"
  # shim_config_path is the path of gvisor-containerd-shim config file.
  local -r shim_config_path="${GVISOR_CONTAINERD_SHIM_CONFIG_PATH:-"${sandbox_root}/config.toml"}"

  if [[ -n "${CONTAINERD_SANDBOX_RUNTIME_HANDLER:-}" ]]; then
    # Setup opt directory for containerd plugins.
    local -r containerd_opt_path="${CONTAINERD_HOME}/opt/containerd"
    mkdir -p "${containerd_opt_path}"
    mkdir -p "${containerd_opt_path}/bin"
    mkdir -p "${containerd_opt_path}/lib"

    local -r containerd_sandbox_pod_annotations=${CONTAINERD_SANDBOX_POD_ANNOTATIONS:-'"dev.gvisor.*"'}
    cat >> "${config_path}" <<EOF
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.${CONTAINERD_SANDBOX_RUNTIME_HANDLER}]
  runtime_type = "${CONTAINERD_SANDBOX_RUNTIME_TYPE:-}"
  pod_annotations = [ ${containerd_sandbox_pod_annotations} ]
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.${CONTAINERD_SANDBOX_RUNTIME_HANDLER}.options]
  TypeUrl = "io.containerd.runsc.v1.options"
  ConfigPath = "${shim_config_path}"

[plugins."io.containerd.internal.v1.opt"]
  path = "${containerd_opt_path}"
EOF
  fi
  chmod 644 "${config_path}"

  # Generate gvisor containerd shim config
  if [[ -n "${GVISOR_CONTAINERD_SHIM_PATH:-}" ]]; then
    cp "${GVISOR_CONTAINERD_SHIM_PATH}" "${containerd_opt_path}/bin"
    # gvisor_platform is the platform to use for gvisor.
    local -r gvisor_platform="${GVISOR_PLATFORM:-"ptrace"}"
    local -r gvisor_net_raw="${GVISOR_NET_RAW:-"true"}"
    mkdir -p "${sandbox_root}"
    cat > "${shim_config_path}" <<EOF
binary_name = "${CONTAINERD_SANDBOX_RUNTIME_ENGINE:-}"
root = "${sandbox_root}"
[runsc_config]
  platform = "${gvisor_platform}"
  net-raw = "${gvisor_net_raw}"
EOF
    if [[ "${gvisor_platform}" == "xemu" ]]; then
      if [[ -f "${CONTAINERD_HOME}/xemu.ko.der" ]]; then
        keyctl padd asymmetric xemu_key \
          "%keyring:.secondary_trusted_keys" < "${CONTAINERD_HOME}/xemu.ko.der"
      fi
      insmod "${CONTAINERD_HOME}/xemu.ko"
    fi
  fi

  # Mount /home/containerd as readonly to avoid security issues.
  mount --bind -o ro,exec "${CONTAINERD_HOME}" "${CONTAINERD_HOME}"

  echo "Restart containerd to load the config change"
  systemctl restart containerd
}

# Set up GCFS daemons.
function gke-setup-gcfs {
  # Write the systemd service file for GCFS FUSE client.
  local -r gcfsd_mnt_dir="/run/gcfsd/mnt"
  local -r layer_cache_dir="/var/lib/containerd/io.containerd.snapshotter.v1.gcfs/snapshotter/layers"
  local -r images_in_use_db_path="/var/lib/containerd/io.containerd.snapshotter.v1.gcfs/gcfsd/images_in_use.db"

  local each_cache_size
  local gcfs_cache_size_flag
  if [[ -z "${GCFSD_CACHE_SIZE_MIB}" ]]; then
    gcfs_cache_size_flag=""
  else
    # GCFSD maintains two caches, each being allocated half of GCFSD_CACHE_SIZE_MIB
    each_cache_size=$((${GCFSD_CACHE_SIZE_MIB} / 2))
    gcfs_cache_size_flag="--max_content_cache_size_mb=${each_cache_size} --max_large_files_cache_size_mb=${each_cache_size}"
  fi

  local gcfs_layer_caching_flag=""
  if [[ "${ENABLE_GCFS_LAYER_CACHING:-false}" == "true" ]]; then
    gcfs_layer_caching_flag="--layer_cache_dir=${layer_cache_dir}"
  fi


  cat <<EOF >/etc/systemd/system/gcfsd.service
# Systemd configuration for Google Container File System service
[Unit]
Description=Google Container File System service
After=network.target
[Service]
Type=simple
LimitNOFILE=infinity
# More aggressive Go garbage collection setting (go/fast/19).
Environment=GOGC=10
ExecStartPre=-/bin/umount -f ${gcfsd_mnt_dir}
ExecStartPre=/bin/mkdir -p ${gcfsd_mnt_dir}
ExecStartPre=/bin/mkdir -p ${layer_cache_dir}
ExecStartPre=/bin/mkdir -p $(dirname ${images_in_use_db_path})
ExecStart=${KUBE_HOME}/bin/gcfsd --mount_point=${gcfsd_mnt_dir} ${gcfs_cache_size_flag} ${gcfs_layer_caching_flag} --images_in_use_db_path=${images_in_use_db_path}
ExecStop=/bin/umount -f ${gcfsd_mnt_dir}
RuntimeDirectory=gcfsd
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
EOF

  # Write the configuration file for GCFS snapshotter.
  # An empty file would work for now.
  mkdir -p /etc/containerd-gcfs-grpc
  touch /etc/containerd-gcfs-grpc/config.toml
  # Write the systemd service file for GCFS snapshotter
  cat <<EOF >/etc/systemd/system/gcfs-snapshotter.service
# Systemd configuration for Google Container File System snapshotter
[Unit]
Description=GCFS snapshotter
After=network.target
Before=containerd.service
[Service]
Environment=HOME=/root
ExecStart=${KUBE_HOME}/bin/containerd-gcfs-grpc --log-level=info --config=/etc/containerd-gcfs-grpc/config.toml
Restart=always
RestartSec=1
[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl start gcfsd.service
  systemctl start gcfs-snapshotter.service
}
