#!/bin/bash
NPD_CUSTOM_PLUGINS_VERSION="${NPD_CUSTOM_PLUGINS_VERSION:-v1.0.4}"
NPD_CUSTOM_PLUGINS_TAR_HASH="${NPD_CUSTOM_PLUGINS_TAR_HASH:-b048ce6daf072a600d9d34997b1e23f8190976f902cf91e6e479aba89202c3ddc5116e2511ce95e842942ca93654f29fa377f1ad93d294f6d07c202d5352c9df}"
NPD_CUSTOM_PLUGINS_RELEASE_PATH="${NPD_CUSTOM_PLUGINS_RELEASE_PATH:-https://storage.googleapis.com/gke-release}"

# Install node problem detector custom plugins.
function install-npd-custom-plugins {
  local -r version="${NPD_CUSTOM_PLUGINS_VERSION}"
  local -r hash="${NPD_CUSTOM_PLUGINS_TAR_HASH}"
  local -r release_path="${NPD_CUSTOM_PLUGINS_RELEASE_PATH}"
  local -r tar="npd-custom-plugins-${version}.tar.gz"

  echo "Downloading ${tar}."
  download-or-bust "${hash}" "${release_path}/npd-custom-plugins/${version}/${tar}"
  local -r dir="${KUBE_HOME}/npd-custom-plugins"
  mkdir -p "${dir}"
  tar xzf "${KUBE_HOME}/${tar}" -C "${dir}" --overwrite
}
