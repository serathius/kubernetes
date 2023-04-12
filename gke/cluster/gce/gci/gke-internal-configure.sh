#!/bin/bash
NPD_CUSTOM_PLUGINS_VERSION="${NPD_CUSTOM_PLUGINS_VERSION:-v1.0.7}"
NPD_CUSTOM_PLUGINS_TAR_HASH="${NPD_CUSTOM_PLUGINS_TAR_HASH:-b697497d6bd35268f588e2baca9f6fd8b9ca081a3401ebc6c6dcdc30a305efdd547231a2884586e28ec79eb5cfb620d15c98a5f9af4946c0d2d72a974f230f5b}"
NPD_CUSTOM_PLUGINS_RELEASE_PATH="${NPD_CUSTOM_PLUGINS_RELEASE_PATH:-${STORAGE_ENDPOINT}/gke-release}"

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
  rm -f "${KUBE_HOME}/${tar}"
}
