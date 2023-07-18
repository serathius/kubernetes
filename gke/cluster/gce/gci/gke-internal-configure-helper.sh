#!/bin/bash

# Functions and vars copied from configure.sh
# --- BEGIN ---
CURL_FLAGS='--fail --silent --show-error --retry 5 --retry-delay 3 --connect-timeout 10 --retry-connrefused'
GCE_METADATA_INTERNAL="http://metadata.google.internal/computeMetadata/v1/instance"
function get-credentials {
  # shellcheck disable=SC2086
  curl ${CURL_FLAGS} \
    -H "Metadata-Flavor: Google" \
    "${GCE_METADATA_INTERNAL}/service-accounts/default/token" \
  | python3 -c 'import sys; import json; print(json.loads(sys.stdin.read())["access_token"])'
}

function is-ubuntu {
  [[ -f "/etc/os-release" && $(grep ^NAME= /etc/os-release) == 'NAME="Ubuntu"' ]]
}
# --- END ---

# Create TLS enabled or disabled kubeconfig files for component static pods.
function gke-internal-create-kubeconfig {
  local component=$1
  local token=$2
  local path=$3
  if [[ "${KUBE_APISERVER_TLS_VERIFY_ENABLED:-}" == "true" ]]; then
    if [[ -z "${KUBE_APISERVER_INTERNAL_ADDRESS}" ]]; then
      echo "Error: TLS verification is enabled, but KUBE_APISERVER_INTERNAL_ADDRESS is missing in env var."
      exit 1
    fi
    echo "Creating TLS verification enabled kubeconfig file for component ${component}"
    cat <<EOF >${path}
apiVersion: v1
kind: Config
users:
- name: ${component}
  user:
    token: ${token}
clusters:
- name: local
  cluster:
    certificate-authority-data: ${CA_CERT}
    server: https://${KUBE_APISERVER_INTERNAL_ADDRESS}:443
    disable-compression: true
contexts:
- context:
    cluster: local
    user: ${component}
  name: ${component}
current-context: ${component}
EOF
  else
    echo "Creating TLS verification disabled kubeconfig file for component ${component}"
    cat <<EOF >${path}
apiVersion: v1
kind: Config
users:
- name: ${component}
  user:
    token: ${token}
clusters:
- name: local
  cluster:
    insecure-skip-tls-verify: true
    server: https://localhost:443
    disable-compression: true
contexts:
- context:
    cluster: local
    user: ${component}
  name: ${component}
current-context: ${component}
EOF
  fi
}

# Returns TLS SNI param for kube-apiserver.
function gke-kube-apiserver-internal-sni-param {
  if [[ "${KUBE_APISERVER_TLS_VERIFY_ENABLED:-}" == "true" ]]; then
    if [[ -z "${KUBE_APISERVER_SERVER_INTERNAL_CERT_PATH}" || -z "${KUBE_APISERVER_SERVER_INTERNAL_KEY_PATH}" || -z "${KUBE_APISERVER_INTERNAL_ADDRESS}" ]]; then
      echo "Error: TLS verification is enabled, but KUBE_APISERVER_SERVER_INTERNAL_CERT_PATH or KUBE_APISERVER_SERVER_INTERNAL_KEY_PATH or KUBE_APISERVER_INTERNAL_ADDRESS is missing in env var."
      exit 1
    fi

    echo " --tls-sni-cert-key=${KUBE_APISERVER_SERVER_INTERNAL_CERT_PATH},${KUBE_APISERVER_SERVER_INTERNAL_KEY_PATH}:${KUBE_APISERVER_INTERNAL_ADDRESS}"
  fi
}

# Writes a cert/key pair for kube-apiserver to server TLS on a GKE internal address.
function write-kube-apiserver-internal-cert-key {
  if [[ "${KUBE_APISERVER_TLS_VERIFY_ENABLED:-}" == "true" ]]; then
    if [[ -z "${KUBE_APISERVER_INTERNAL_TLS_CERT}" || -z "${KUBE_APISERVER_INTERNAL_TLS_KEY}" ]]; then
      echo "Error: TLS verification is enabled, but KUBE_APISERVER_INTERNAL_TLS_CERT or KUBE_APISERVER_INTERNAL_TLS_KEY is missing in env var."
      exit 1
    fi

    local -r pki_dir="/etc/srv/kubernetes/pki"
    mkdir -p "${pki_dir}"

    KUBE_APISERVER_SERVER_INTERNAL_CERT_PATH="${pki_dir}/internal-apiserver.crt"
    write-pki-data "${KUBE_APISERVER_INTERNAL_TLS_CERT}" "${KUBE_APISERVER_SERVER_INTERNAL_CERT_PATH}"
    KUBE_APISERVER_SERVER_INTERNAL_KEY_PATH="${pki_dir}/internal-apiserver.key"
    write-pki-data "${KUBE_APISERVER_INTERNAL_TLS_KEY}" "${KUBE_APISERVER_SERVER_INTERNAL_KEY_PATH}"
  fi
}

# Add entry to hostfile to redirect internal name to master internal IP.
function setup-kube-apiserver-internal-address-redirect {
  if [[ "${KUBE_APISERVER_TLS_VERIFY_ENABLED:-}" == "true" ]]; then
    if [[ -z "${KUBE_APISERVER_INTERNAL_ADDRESS}" ]]; then
      echo "Error: TLS verification is enabled, but KUBE_APISERVER_INTERNAL_ADDRESS is missing in env var."
      exit 1
    fi

    local internal_ip=$(ifconfig eth0 | grep 'inet ' | awk '{print $2}')
    echo "Master IPv4 internal IP is ${internal_ip}"
    echo "${internal_ip} ${KUBE_APISERVER_INTERNAL_ADDRESS}" >>/etc/hosts
  fi
}

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

function setup_master_prom_to_sd_monitor_component {
  local -r manifests_dir="${KUBE_HOME}/kube-manifests/kubernetes/gci-trusty"
  mkdir -p "${manifests_dir}/master-prom-to-sd-monitor"

  cp "${manifests_dir}/internal-master-prom-to-sd-monitor-rbac.yaml" "${manifests_dir}/master-prom-to-sd-monitor"
  setup-addon-manifests "addons" "master-prom-to-sd-monitor"

  create-static-auth-kubeconfig-for-component master-prom-to-sd-monitor
}

function create-static-auth-kubeconfig-for-component {
  local component=$1
  echo "Creating token for component ${component}"
  local token="$(secure_random 32)"
  append_or_replace_prefixed_line /etc/srv/kubernetes/known_tokens.csv "${token}," "system:${component},uid:system:${component}${AUTH_COMPONENTS_GROUP:+,$AUTH_COMPONENTS_GROUP}"
  create-kubeconfig ${component} ${token}
  echo -n ${token} > /etc/srv/kubernetes/${component}/token
}

function gke-internal-master-start {
  echo "Internal GKE configuration start"
  compute-master-manifest-variables

  configure-sshd

  write-kube-apiserver-internal-cert-key
  setup-kube-apiserver-internal-address-redirect

  start_internal_cluster_autoscaler
  start_pod_autoscaler
  setup_master_prom_to_sd_monitor_component
  if generate-token-for-mastertest; then
    create-static-auth-kubeconfig-for-component mastertest
  fi

  if [[ -n "${KUBE_BEARER_TOKEN:-}" ]]; then
    echo "setting up local admin kubeconfig"
    create-kubeconfig "local-admin" "${KUBE_BEARER_TOKEN}"
    echo "export KUBECONFIG=/etc/srv/kubernetes/local-admin/kubeconfig" > /etc/profile.d/kubeconfig.sh
  fi

  configure-osconfig-agent

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
function gke-configure-node-sysctls {
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

  # Take a snapshot of the current sysctls and store them in a file. This will
  # be used as the base for monitoring sysctl changes by NPD custom plugin
  # sysctl-monitor.
  #
  # The directory was created in configure.sh.
  sudo sysctl -a > "${KUBE_HOME}/npd-custom-plugins/configs/init-sysctls.conf"
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

# Default containerd config TOML file
CONTAINERD_CONFIG_FILE="/etc/containerd/config.toml"
# Directory containing $CONTAINERD_CONFIG_FILE
CONTAINERD_CONFIG_ROOT=$(dirname "${CONTAINERD_CONFIG_FILE}")
# Directory containing domain-specific config for containerd CRI
# registry hostpath
CONTAINERD_CRI_REGISTRY_HOSTPATH_CONFIG_ROOT="${CONTAINERD_CONFIG_ROOT}/hosts.d"
# Directory containing certificates for containerd CRI registry hostpath
CONTAINERD_CRI_REGISTRY_HOSTPATH_CERTS_ROOT="${CONTAINERD_CONFIG_ROOT}/certs.d"
# GSM API URL
# TODO(b/283980355): define an override mechanism for TPC
GSM_ENDPOINT="https://secretmanager.googleapis.com"
# Default file names for private CA certificate
PRIVATE_CA_CRT_NAME="ca.crt"
# Default file names for private CA certificate metadata
PRIVATE_CA_CRT_METADATA_NAME="metadata.json"

# Downloads and installs a CA certificate from Google Secret Manager (GSM).
# On successful download, it will install the certificate under
# containerd_certs_dir/cert_url/ca.crt, as well as the secret metadata under
# containerd_certs_dir/cert_url/metadata.json.
# This function extract HTTP error codes to distinguish between user errors
# (e.g. typos, access config errors) and system errors (e.g. GSM outage).
function install-gsm-certificate() {
  local -r cert_url="${1:-}"
  if [[ -z "${cert_url}" ]]; then
    echo "Certificate URL must be specified"
    return 1
  fi
  local -r cert_dir="${2:-}"
  if [[ -z "${cert_dir}" ]]; then
    echo "Certificate directory must be specified"
    return 1
  fi
  local -r token="$(get-credentials)"
  if [[ -z "${token}" ]]; then
    echo "Failed to get credentials from metadata server"
    return 1
  fi
  local -r curl_headers="Authorization: Bearer ${token}"
  local -r api_url="${GSM_ENDPOINT}/v1/${cert_url}"
  local -r payload_file="/tmp/gsm-payload.json"
  # shellcheck disable=SC2206
  local -r gsm_curl_flags=($CURL_FLAGS -H "${curl_headers}" -Lo "${payload_file}")
  local curl_error http_code

  # shellcheck disable=SC2086
  if ! curl_error=$(curl "${gsm_curl_flags[@]}" "${api_url}" 2>&1); then
    http_code=$(echo "${curl_error}" | sed -nE 's/^.*([0-9]{3})$/\1/p')
    if (( http_code >= 400 && http_code <= 499 )); then
      echo "User error pulling certificate metadata \"${cert_url}\" from GSM, code: ${http_code}."
    elif (( http_code >= 500 )); then
      echo "Internal error pulling certificate metadata \"${cert_url}\" from GSM, code: ${http_code}."
    else
      echo "Internal error pulling certificate metadata \"${cert_url}\" from GSM: ${curl_error}"
    fi
    return 1
  fi
  local -r metadata_file="${cert_dir}/${PRIVATE_CA_CRT_METADATA_NAME}"
  mv "${payload_file}" "${metadata_file}"
  chmod 444 "${metadata_file}"

   # shellcheck disable=SC2086
  if ! curl_error=$(curl "${gsm_curl_flags[@]}" "$api_url:access" 2>&1); then
    http_code=$(echo "$curl_error" | sed -nE 's/^.*([0-9]{3})$/\1/p')
    if (( http_code >= 400 && http_code <= 499 )); then
      echo "User error pulling certificate \"${cert_url}\" from GSM, code: ${http_code}."
    elif (( http_code >= 500 )); then
      echo "Internal error pulling certificate \"${cert_url}\" from GSM, code: ${http_code}."
    else
      echo "Internal error pulling certificate \"${cert_url}\" from GSM: ${curl_error}"
    fi
    return 1
  fi
  local -r cert_file="${cert_dir}/${PRIVATE_CA_CRT_NAME}"
  jq -r '.payload.data' "${payload_file}" | base64 -d > "${cert_file}"
  chmod 444 "${cert_file}"
  rm "${payload_file}"
}

# Create a containerd host config file (using containerd hostpath configuration)
# under ${CONTAINERD_CRI_REGISTRY_HOSTPATH_CONFIG_ROOT}/${domain}
# It expects two arguments:
# - domain
# - CA certificate path
function add-containerd-cri-hostpath-registry-private-ca() {
  local -r domain="${1:-}"
  if [[ -z "${domain}" ]]; then
    echo "Domain must be specified"
    return 1
  fi
  local -r ca_cert_path="${2:-}"
  if [[ -z "${ca_cert_path}" ]]; then
    echo "CA certificate path must be specified"
    return 1
  fi

  local -r host_config_dir="${CONTAINERD_CRI_REGISTRY_HOSTPATH_CONFIG_ROOT}/${domain}"
  mkdir -p "${host_config_dir}"
  local -r host_config_path="${host_config_dir}/hosts.toml"
  cat > "${host_config_path}" <<EOF
server = "https://${domain}"

[host."https://${domain}"]
  ca = "${ca_cert_path}"
EOF
  chmod 644 "${host_config_path}"
}

function configure-containerd-customization {
  echo "Configuring private CA for container registries using GSM"
  if is-ubuntu; then
    echo "containerd customization is only supported on COS, skipping"
    return
  fi
  if [[ -n "${CONTAINERD_PRIVATE_CA_GSM_CERT:-}" ]]; then
    mkdir -p "${CONTAINERD_CRI_REGISTRY_HOSTPATH_CERTS_ROOT}"

    # Config must be in a predefined JSON format.
    # See go/gke-private-ca-kubenv-source.
    local cert_url cert_dir
    echo "${CONTAINERD_PRIVATE_CA_GSM_CERT}" | jq -c '.secret_configs[]' | while read -r config; do
      cert_url="$(echo "${config}" | jq -r '.secret_url')"
      cert_dir="${CONTAINERD_CRI_REGISTRY_HOSTPATH_CERTS_ROOT}/${cert_url}"
      mkdir -p "${cert_dir}"
      if ! install-gsm-certificate "${cert_url}" "${cert_dir}"; then
        # Certificate installation failed, no need to write containerd config.
        echo "Failed to install certificate \"${cert_url}\""
        continue
      fi
      echo "Installed certificate \"${cert_url}\""
      echo "${config}" | jq -r '.fqdns[]' | while read -r domain; do
        add-containerd-cri-hostpath-registry-private-ca "${domain}" "${cert_dir}/${PRIVATE_CA_CRT_NAME}"
      done
    done
  fi
}

# If your new containerd feature uses CRI registry hostpath config model,
# update this function to include it.
function use-containerd-cri-registry-hostpath {
  if is-ubuntu; then
    echo "false"
    return
  fi
  if [[ -n "${CONTAINERD_PRIVATE_CA_GSM_CERT:-}" ]]; then
    echo "true"
    return
  fi
  echo "false"
}

# add-containerd-cri-hostpath-registry-mirrors receives a domain and a variable
# number of mirrors as args. If the hosts.toml file already exists
# for given domain, it just appends to it.
function add-containerd-cri-hostpath-registry-mirrors {
  local -r domain="${1:-}"
  if [[ -z "${domain}" ]]; then
    echo "Mirror must be passed"
    return 1
  fi
  shift

  local -r host_config_dir="${CONTAINERD_CRI_REGISTRY_HOSTPATH_CONFIG_ROOT}/${domain}"
  mkdir -p "${host_config_dir}"
  local -r host_config_path="${host_config_dir}/hosts.toml"
  if [[ ! -e "${host_config_path}" ]]; then
    cat > "${host_config_path}" <<EOF
server = "https://${domain}"

EOF
    chmod 644 "${host_config_path}"
  fi
  local mirror
  while (( "$#" )); do
    mirror="${1}"
    cat >> "${host_config_path}" <<EOF
[host."https://${mirror}"]
  capabilities = ["pull", "resolve"]
EOF
    shift
  done
}

function gke-setup-containerd {
  local -r CONTAINERD_HOME="/home/containerd"
  mkdir -p "${CONTAINERD_HOME}"

  echo "Generating containerd config"
  local -r config_path="${CONTAINERD_CONFIG_FILE:-"/etc/containerd/config.toml"}"
  mkdir -p "${CONTAINERD_CONFIG_ROOT}"
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
  sandbox_image = "${KUBE_DOCKER_REGISTRY}/${GKE_CONTAINERD_INFRA_CONTAINER}"
[plugins."io.containerd.grpc.v1.cri".cni]
  bin_dir = "${KUBE_HOME}/bin"
  conf_dir = "/etc/cni/net.d"
  conf_template = "${cni_template_path}"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
  SystemdCgroup = ${systemdCgroup}
EOF

  # Setup mirrors based on the CRI registry config model
  if [[ "$(use-containerd-cri-registry-hostpath)" == "true" ]]; then
    cat >> "${config_path}" <<EOF
# IMPORTANT: CRI REGISTRY CONFIGURATION WAS SWITCHED TO THE HOSTPATH CONFIG MODEL.
# IF YOU'RE CUSTOMIZING CONTAINERD CONFIG PLEASE ENSURE YOU USE THE NEW MODEL.
[plugins."io.containerd.grpc.v1.cri".registry]
  config_path = "${CONTAINERD_CRI_REGISTRY_HOSTPATH_CONFIG_ROOT}"
EOF
    add-containerd-cri-hostpath-registry-mirrors "docker.io" \
      "mirror.gcr.io" "registry-1.docker.io"
  else
    cat >> "${config_path}" <<EOF
[plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]
  endpoint = ["https://mirror.gcr.io","https://registry-1.docker.io"]
EOF
  fi

  configure-containerd-customization

  if [[ "${ENABLE_CONTAINERD_METRICS:-}" == "true" ]]; then
    cat >> "${config_path}" <<EOF
[metrics]
 address = "127.0.0.1:1338"
EOF
  fi

  if [[ "${ENABLE_GCFS:-}" == "true" ]]; then
    gke-setup-gcfs
    cat >> "${config_path}" <<EOF
[plugins."io.containerd.grpc.v1.cri".containerd]
  default_runtime_name = "runc"
  snapshotter = "gcfs"
  disable_snapshot_annotations = false
  discard_unpacked_layers = true
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
  discard_unpacked_layers = true
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

  local -r gvisor_platform="${GVISOR_PLATFORM:-"ptrace"}"

  # If we can install via the installer container, do so.
  # The installation container:
  # 1. Installs the requred binaries (runsc and containerd-shim) to the expected
  # directories (under /home/containerd/...).
  # 2. Writes the required gVisor config.toml file to /run/containerd/runsc/config.toml.
  #
  # We do this here so that we can dynamically load versions of gVisor by downloading the
  # passed container image. The installation mounts root and runs as a priviledged container
  # so that it can write binaries and files to the host's file system and inspect the
  # system configuration so that it can use flags in specific contexts (e.g. Is this an
  # x86 machine? If so, set the 'core-tags' flag to mitigate side-channel attacks.)
  # Note that 'ctr' will not pull the image itself as that is done in config.sh.
  #
  # See: http://google3/cloud/kubernetes/distro/containers/gvisor
  if [[ -n "${GVISOR_INSTALLER_IMAGE_HASH:-}" ]]; then
    local -r installer_image_hash="${GVISOR_INSTALLER_IMAGE_HASH:-}"
    local -r installer_image="${KUBE_DOCKER_REGISTRY}/gke-gvisor-installer@sha256:${installer_image_hash}"
    ctr -n k8s.io run --rm --mount=type=bind,src=/,dst=/host,options=rbind:rw --privileged "${installer_image}" gvisor-installer
  # Generate gvisor containerd shim config
  elif [[ -n "${GVISOR_CONTAINERD_SHIM_PATH:-}" ]]; then
    cp "${GVISOR_CONTAINERD_SHIM_PATH}" "${containerd_opt_path}/bin"
    # gvisor_platform is the platform to use for gvisor.
    local -r gvisor_net_raw="${GVISOR_NET_RAW:-"true"}"
    local -r gvisor_seccomp="${GVISOR_SECCOMP:-"true"}"
    local -r gvisor_core_tags="${GVISOR_CORE_TAGS:-"false"}"
    local -r gvisor_nvidia="${GVISOR_NVIDIA:-"false"}"
    mkdir -p "${sandbox_root}"
    cat > "${shim_config_path}" <<EOF
binary_name = "${CONTAINERD_SANDBOX_RUNTIME_ENGINE:-}"
root = "${sandbox_root}"
[runsc_config]
  platform = "${gvisor_platform}"
  net-raw = "${gvisor_net_raw}"
  oci-seccomp = "${gvisor_seccomp}"
  systemd-cgroup = "${systemdCgroup}"
  enable-core-tags = "${gvisor_core_tags}"
  nvproxy = "${gvisor_nvidia}"
EOF
    if [[ -n "${GVISOR_METRIC_SERVER:-}" ]]; then
      echo "  metric-server = \"${GVISOR_METRIC_SERVER}\"" >> "${shim_config_path}"
    fi
  fi

  if [[ "${gvisor_platform}" == "xemu" ]]; then
    # COS versions cos-97-16919-29-21 and after contain XEMU in the base
    # image.
    modprobe xemu
  fi

  # Mount /home/containerd as readonly to avoid security issues.
  mount --bind -o ro,exec "${CONTAINERD_HOME}" "${CONTAINERD_HOME}"

  echo "Restart containerd to load the config change"
  systemctl restart containerd
}

# Manipulate SMT settings for the node. GKE Sandbox by default
# disables SMT for vulnerable nodes.
function configure-smt {
  declare -r smt_op="${GVISOR_ENABLE_SMT:-}"
  declare -r smt_path="/sys/devices/system/cpu/smt/control"
  local smt_state=$(cat ${smt_path})
  echo "SMT in initial state: ${smt_state}"
  if [[ "${smt_op}" == "true" ]]; then
    echo "Enabling SMT for node."
    echo "on" > "${smt_path}" || true
  elif [[ "${smt_op}" == "false" ]]; then
    echo "Disabling SMT for node."
    echo "off" > "${smt_path}" || true
  fi
  smt_state=$(cat ${smt_path})
  echo "SMT in final state: ${smt_state}"
}

# If we specify GKE_ADDON_REGISTRY_OVERRIDE, it will replace all occurrences
# of 'gke.gcr.io', with the specified value in all the manifests.
# This is useful when running in test or staging, example:
# gke.gcr.io -> eu.gcr.io/gke-release-staging
function setup-gke-addon-registry {
  local -r manifests_dir="${KUBE_HOME}/kube-manifests/kubernetes/gci-trusty"
  local -r gke_addon_registry_override="${GKE_ADDON_REGISTRY_OVERRIDE:-}"
  if [[ -n $gke_addon_registry_override ]] ; then
    # some .manifest files are in yaml format, while others are in json
    find "${manifests_dir}" -name \*.yaml -or -name \*.yaml.in -or -name \*.manifest | \
      xargs sed -ri "s@(image:\s.*)gke.gcr.io@\1${gke_addon_registry_override}@"
    find "${manifests_dir}" -name \*.manifest -or -name \*.json | \
      xargs sed -ri "s@(image\":\s+\")gke.gcr.io@\1${gke_addon_registry_override}@"
  fi
}

# Configure node-problem-detector flags.
#
# This function expects no arguments. It currently configures NPD to operate as
# a stand-alone service on a COS/GCI image.
#
# This function
#   - is a no-op, if NODE_PROBLEM_DETECTOR_CUSTOM_FLAGS is already set (on
#     instance metadata). (Note that it is not recommended to set
#     NODE_PROBLEM_DETECTOR_CUSTOM_FLAGS on instance metadata from google3).
#   - sets NODE_PROBLEM_DETECTOR_CUSTOM_FLAGS with the flags to be used by NPD
#     in function start-node-problem-detector, otherwise.
function gke-configure-node-problem-detector {
  local flags="${NODE_PROBLEM_DETECTOR_CUSTOM_FLAGS:-}"
  if [[ ! -z "${flags}" ]]; then
    return
  fi

  local -r km_config="${KUBE_HOME}/node-problem-detector/config/kernel-monitor.json"
  # TODO(random-liu): Handle this for alternative container runtime.
  local -r dm_config="${KUBE_HOME}/node-problem-detector/config/docker-monitor.json"
  local -r sm_config="${KUBE_HOME}/node-problem-detector/config/systemd-monitor.json"

  local -r custom_km_config="${KUBE_HOME}/node-problem-detector/config/kernel-monitor-counter.json"
  local -r custom_sm_config="${KUBE_HOME}/node-problem-detector/config/systemd-monitor-counter.json"

  local -r sd_exporter_config="${KUBE_HOME}/node-problem-detector/config/exporter/stackdriver-exporter.json"

  # TODO(b/235657451): add "net-cgroup-system-stats-monitor.json"
  local -r system_stats_monitor="${KUBE_HOME}/node-problem-detector/config/system-stats-monitor.json"

  local custom_plugin_monitors="${custom_km_config},${custom_sm_config}"

  gke-configure-npd-custom-plugins
  if [[ -n "${GKE_NPD_CUSTOM_PLUGINS_CONFIG}" ]]; then
    custom_plugin_monitors+=",${GKE_NPD_CUSTOM_PLUGINS_CONFIG}"
  fi

  if [[ "${ENABLE_NODE_REGISTRATION_CHECKER:-}" == "true" && -e ${KUBE_HOME}/npd-custom-plugins/configs/node-registration-checker-monitor.json ]]; then
    local node_registration_checker_config=",${KUBE_HOME}/npd-custom-plugins/configs/node-registration-checker-monitor.json"
  fi

  local -r local_ssd_config="${KUBE_HOME}/npd-custom-plugins/configs/local-ssd-monitor.json"

  flags="${NPD_TEST_LOG_LEVEL:-"--v=2"} ${NPD_TEST_ARGS:-}"
  flags+=" --logtostderr"
  flags+=" --config.system-log-monitor=${km_config},${dm_config},${sm_config},${local_ssd_config}${node_registration_checker_config:-}"
  flags+=" --config.system-stats-monitor=${system_stats_monitor}"
  flags+=" --config.custom-plugin-monitor=${custom_plugin_monitors}"
  flags+=" --exporter.stackdriver=${sd_exporter_config}"
  local -r npd_port=${NODE_PROBLEM_DETECTOR_PORT:-20256}
  flags+=" --port=${npd_port}"
  if [[ -n "${EXTRA_NPD_ARGS:-}" ]]; then
    flags+=" ${EXTRA_NPD_ARGS}"
  fi

  NODE_PROBLEM_DETECTOR_CUSTOM_FLAGS="${flags}"
}

# Configure NPD custom plugins.
#
# This function expects no arguments.
#
# This function configures NPD custom plugins and sets
# GKE_NPD_CUSTOM_PLUGINS_CONFIG with the NPD flags needed to enable the plugins.
function gke-configure-npd-custom-plugins {
  local -r config_dir="${KUBE_HOME}/npd-custom-plugins/configs"

  # Configure sysctl monitor.
  GKE_NPD_CUSTOM_PLUGINS_CONFIG="${config_dir}/sysctl-monitor.json"

  # the two json configs only includes gcfs-snapshotter and gcfsd service for now
  if [[ "${ENABLE_GCFS:-}" == "true" ]]; then
    GKE_NPD_CUSTOM_PLUGINS_CONFIG+=",${config_dir}/systemd-monitor-health.json,${config_dir}/systemd-monitor-restart.json,${config_dir}/gcfs-snapshotter-missing-layer-monitor.json"
  fi
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
ExecStart=${KUBE_HOME}/bin/gcfsd --mount_point=${gcfsd_mnt_dir} ${gcfs_cache_size_flag} ${gcfs_layer_caching_flag} --images_in_use_db_path=${images_in_use_db_path} --enable_pull_secret_keychain
ExecStop=-/bin/umount -f ${gcfsd_mnt_dir}
RuntimeDirectory=gcfsd
Restart=on-failure
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
# Disable restart rate limiting
StartLimitIntervalSec=0
[Service]
Environment=HOME=/root
ExecStart=${KUBE_HOME}/bin/containerd-gcfs-grpc --log-level=info --config=/etc/containerd-gcfs-grpc/config.toml --enable-image-proxy-keychain-client
Restart=always
RestartSec=1
[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl start gcfsd.service
  systemctl start gcfs-snapshotter.service
}

function gke-create-gpu-config {
  local -r gpu_config_file="/etc/nvidia/gpu_config.json"
  mkdir -p "$(dirname "${gpu_config_file}")"
  local -r dir="${KUBE_HOME}/kube-manifests/kubernetes/gci-trusty/gpu"

  local gpu_partition_size=""
  if [ -n "${GPU_PARTITION_SIZE:-}" ]; then
    gpu_partition_size="${GPU_PARTITION_SIZE}"
  fi

  local max_time_shared_clients_per_gpu=""
  if [ -n "${MAX_TIME_SHARED_CLIENTS_PER_GPU:-}" ]; then
      max_time_shared_clients_per_gpu="${MAX_TIME_SHARED_CLIENTS_PER_GPU}"
  fi

  local max_shared_clients_per_gpu=""
  if [ -n "${MAX_SHARED_CLIENTS_PER_GPU:-}" ]; then
      max_shared_clients_per_gpu="${MAX_SHARED_CLIENTS_PER_GPU}"
  fi

  local gpu_sharing_strategy=""
  if [ -n "${GPU_SHARING_STRATEGY:-}" ]; then
      gpu_sharing_strategy="${GPU_SHARING_STRATEGY}"
  fi

  python3 "${dir}/generate-gpu-config.py" \
    --gpu-partition-size="${gpu_partition_size}" \
    --max-time-shared-clients-per-gpu=${max_time_shared_clients_per_gpu} \
    --max-shared-clients-per-gpu=${max_shared_clients_per_gpu} \
    --gpu-sharing-strategy=${gpu_sharing_strategy} \
    --file-path=${gpu_config_file}

  # Setup all GPUs to EXCLUSIVE mode (https://docs.nvidia.com/deploy/mps/index.html#topic_3_3_1_2).
  # Setup systemd service to start MPS control daemon.
  if [[ "${GPU_SHARING_STRATEGY:-}" == "mps" ]]; then
    cat <<EOF >/etc/systemd/system/nvidia-mps.service
[Unit]
Description=NVIDIA MPS

[Service]
Type=simple
Restart=always
RestartSec=10
RemainAfterExit=yes
ExecStartPre=/home/kubernetes/bin/nvidia/bin/nvidia-smi -c EXCLUSIVE_PROCESS
ExecStart=/bin/bash -c 'PATH=$PATH:/home/kubernetes/bin/nvidia/bin exec nvidia-cuda-mps-control -d'
ExecStop=echo quit | nvidia-cuda-mps-control

[Install]
WantedBy=multi-user.target
EOF

    cat <<EOF >/etc/systemd/system/nvidia-mps.path
[Unit]
Description=NVIDIA MPS path

[Path]
PathExists=/home/kubernetes/bin/nvidia/bin/nvidia-cuda-mps-control
Unit=nvidia-mps.service

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl start nvidia-mps.path
  fi
}

# Set up the inplace agent.
function gke-setup-inplace {
  # Setup inplace master pod manifests: inplace-run-once downloads the
  # component manifests to
  # ${KUBE_HOME}/kube-manifests/kubernetes/gci-trusty/in-place and -setup moves the
  # master pod manifests to /etc/kubernetes/manifests before cluster starts up.
  echo "Setup inplace master pod manifests"
  local src_dir="${KUBE_HOME}/kube-manifests/kubernetes/gci-trusty/in-place"
  if [[ -d  "${src_dir}" ]]; then
    copy-manifests "${src_dir}" "/etc/kubernetes/manifests"
  fi
  cp ${KUBE_HOME}/inplace/in-place-status.yaml ${KUBE_HOME}/inplace/in-place-status.init.yaml
  cat <<EOF >/etc/systemd/system/inplace.service
# Systemd configuration for inplace server
[Unit]
Description=GKE component inplace update agent
[Service]
Restart=always
RestartSec=10
RemainAfterExit=yes
RemainAfterExit=yes
ExecStartPre=/bin/chmod 544 /home/kubernetes/bin/inplace
Restart=always
RestartSec=10
ExecStart=${KUBE_HOME}/bin/inplace --home_path=${KUBE_HOME}/inplace --inplace_binary_path=${KUBE_HOME}/bin/inplace
[Install]
WantedBy=kubernetes.target
EOF

  systemctl daemon-reload
  systemctl start inplace.service
}

# Configure sshd as required for Autopilot nodes
function gke-configure-autopilot-sshd {
  echo "Reconfiguring sshd for Autopilot"
  echo "${GKE_AUTOPILOT_SSHD_CONFIG}" >> "/etc/ssh/sshd_config"
  systemctl restart sshd
  echo "Restarted sshd"
}

function deploy-etcd-via-kube-up {
  [[ "${ETCD_CRP:-}" != "true" ]]
}
function deploy-kube-scheduler-via-kube-up {
  [[ "${KUBE_SCHEDULER_CRP:-}" != "true" ]]
}

function deploy-kube-controller-manager-via-kube-up {
  [[ "${KUBE_CONTROLLER_MANAGER_CRP:-}" != "true" ]]
}

function generate-token-for-mastertest {
  [[ "${MASTERTEST_TOKEN_ENABLED:-false}" == "true" ]]
}

# Tweak SSH daemon config.
function configure-sshd {
  mkdir -p /etc/systemd/system/sshd.service.d
  cat <<EOF >/etc/systemd/system/sshd.service.d/gke.conf
[Service]
OOMScoreAdjust=-1000
EOF

  systemctl daemon-reload
  systemctl restart sshd
}

# Configure OS Config agent. Activation is controlled by VM metadata.
function configure-osconfig-agent {
  mkdir -p /etc/systemd/system/google-osconfig-agent.service.d
  cat <<EOF >/etc/systemd/system/google-osconfig-agent.service.d/gke.conf
[Service]
CPUAccounting=true
MemoryAccounting=true
CPUQuota=5%
MemoryHigh=50M
MemoryMax=100M
EOF

  systemctl daemon-reload
  systemctl restart google-osconfig-agent
}

function install-node-registration-checker {
  if [[ "${KUBERNETES_MASTER:-false}" == "true" ]]; then
      echo "Skipping installation of Node Registration Checker. This is a master node"
      return
  elif [[ "${ENABLE_NODE_REGISTRATION_CHECKER:-false}" == "false"  ]]; then
      echo "Skipping installation of Node Registration Checker. Node Registration Checker is not enabled for this version"
      return
  elif [[ ! -e ${KUBE_BIN}/node-registration-checker.sh ]]; then
      echo "Skipping installation of Node Registration Checker. Node Registration Checker script is not present"
      return
  fi

  chmod 544 "${KUBE_BIN}/node-registration-checker.sh"

  echo "Installing Node Registration Checker service"
  # Write the systemd service file for node registration checker.
  cat <<EOF >/etc/systemd/system/gke-node-reg-checker.service
[Unit]
Description=Check node registration with API server

[Service]
Type=simple
ExecStart=${KUBE_BIN}/node-registration-checker.sh
StandardOutput=journal+console

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl start gke-node-reg-checker.service
}

function configure-auth-provider-gcp {
  # Keep in sync with --image-credential-provider-config in cloud/kubernetes/distro/legacy/kube_env.go
  cat > "/etc/srv/kubernetes/cri_auth_config.yaml" << EOF
kind: CredentialProviderConfig
apiVersion: kubelet.config.k8s.io/v1
providers:
  - name: auth-provider-gcp
    apiVersion: credentialprovider.kubelet.k8s.io/v1
    matchImages:
    - "container.cloud.google.com"
    - "gcr.io"
    - "*.gcr.io"
    - "*.pkg.dev"
    args:
    - get-credentials
    - --v=3
    defaultCacheDuration: 1m
EOF
}

# See b/289436536 for context.
function gke-configure-multinic-no-hostname {
  echo "Stop accepting DHCP hostname from non-eth0 interfaces"
  if is-ubuntu; then
    echo "Only COS is accepting DHCP hostname, skipping"
    return
  fi
  default_net_conf="/usr/lib/systemd/network/99-default.network"
  new_config="/etc/systemd/network/90-non-eth0.network"
  if [[ -e "${default_net_conf}" ]]; then
    cp "${default_net_conf}" "${new_config}"
    sed -i 's/\[Match\]/\[Match\]\nName=!eth0/g' "${new_config}"
    sed -i 's/\[DHCP\]/\[DHCP\]\nUseHostname=false/g' "${new_config}"
  else
    echo "Error: Default network config not found: ${default_net_conf}"
    exit 1
  fi
  systemctl restart systemd-networkd
}
