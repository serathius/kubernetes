# Copyright 2024 The GKE Authors.
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

"""Test library to test installable code."""

import argparse
import installable
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from typing import Any
import unittest


def credentials_in_log(log: str) -> bool:
  """Returns true if the machine's credentials are in a given log string."""
  regex = re.compile(installable.get_gce_credentials())
  return regex.match(log)

container_content = """{
	"kind":"container",
	"apiVersion": "installable.gke.io/v1",
	"metadata":{
	  "name":"my-container"
	},
	"os":"linux",
	"arch":"MULTI","version":"1.0.1",
  "remoteURL":"gcr.io/gke-release-staging/gke-distroless/bash",
  "digest":"9bd9f35657b03f55a00a33feac0500ee183dcfd5f7f1982cd35a7a032953d466",
	"digestAlgo":"sha256",
  "run": {
	  "containerArgs":["echo", "hello"]
  }
}"""

garbage = 'this_is_garbage'

class FakeCtr(installable.Ctr):
  """FakeCtr fakes calls to the ctr executable."""
  images = {}

  def download(self, url: str) -> subprocess.CompletedProcess:
    if garbage in url:
      return subprocess.CalledProcessError(cmd='', returncode=255, stderr="This was a failed download.")
    self.images[url] = True
    return subprocess.CompletedProcess(args='', returncode=0, stdout='', stderr='')

  def list_images(self) -> subprocess.CompletedProcess:
    images = []
    for image in self.images.keys():
      images.append(image)
    std_out = ','.join(images)
    return subprocess.CompletedProcess(args='', returncode=0, stdout=std_out)

  def delete(self, url: str):
    if not url in self.images.keys():
      return subprocess.CalledProcessError(args='', returncode=1, stderr="no image found")
    self.images.pop(url)

  def run(self, container_name: str, url: str, ctr_args: list, container_args: list) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args='', returncode=0, stdout='')


class ContainerTests(unittest.TestCase):
  """ContainerTests are tests for the "container" kind."""

  def setUp(self):
    super().setUp()
    inst = json.loads(container_content)
    container = installable.parse_installable(inst)
    if container.is_preloaded():
      installable.ctr.delete(container.get_url())
    if isinstance(installable.ctr, FakeCtr):
      installable.ctr.images = {}

  def test_parse(self):
    """Tests that a given container blob parses into a container object."""
    inst = installable.parse_installable(json.loads(container_content))
    self.assertTrue(isinstance(inst, installable.Container))
    self.assertEqual(inst.name(), 'my-container')

  def test_preload(self):
    """Tests the download function of the container."""
    inst = json.loads(container_content)
    with self.assertLogs(logger=installable.LOGGER, level=logging.INFO) as logs:
      with installable.parse_installable(inst) as obj:
        installable.process_installable(installable=obj, download=True)
    self.assertEqual(logs.output, ['INFO:installable:Installable not preloaded...downloading',
   'INFO:installable:Running container '
   'gcr.io/gke-release-staging/gke-distroless/bash@sha256:9bd9f35657b03f55a00a33feac0500ee183dcfd5f7f1982cd35a7a032953d466 '
   'succeeded.'])
    container = installable.Container(inst)
    self.assertTrue(container.is_preloaded())

  def test_bad_url(self):
    """Tests that downloads fail given a bad URL."""
    container = json.loads(container_content)
    container['remoteURL'] = garbage
    inst = installable.parse_installable(container)
    with self.assertLogs(installable.LOGGER):
      with self.assertRaisesRegex(installable.DownloadError, 'Failed to download container'):
        installable.process_installable(installable=inst, download=True)

  def test_already_preloaded(self):
    container = installable.parse_installable(json.loads(container_content))
    installable.ctr.download(container.get_url())
    self.assertTrue(container.is_preloaded())
    with self.assertLogs(logger=installable.LOGGER, level=logging.INFO) as logs:
      installable.process_installable(installable=container, download=True)
    self.assertEqual(logs.output, ['INFO:installable:Running container '
   'gcr.io/gke-release-staging/gke-distroless/bash@sha256:9bd9f35657b03f55a00a33feac0500ee183dcfd5f7f1982cd35a7a032953d466 '
   'succeeded.'])


  def test_not_preloaded(self):
    container = installable.parse_installable(json.loads(container_content))
    self.assertFalse(container.is_preloaded())
    with self.assertRaisesRegex(installable.PreloadError, f'Installable {container.name()} not preloaded.'):
      installable.process_installable(installable=container, download=False)
    self.assertFalse(container.is_preloaded())

  def test_gvisor_integration(self):

    gvisor_content = """{
      "kind":"Container",
      "apiVersion": "installable.gke.io/v1",
      "metadata":{
        "name":"gvisor"
      },
      "os":"linux",
      "arch":"MULTI",
      "version":"20241025.0_RC00",
      "remoteURL":"gcr.io/gke-release-staging/gke-gvisor-installer",
      "digest":"0c3e3ac8b7bfad7db5df9fe3c3d67eff11ce33ed4391a6ce323a5fced0ccef33",
      "digestAlgo":"sha256",
      "run": {
        "ctrArgs":["--rm", "--mount", "type=bind,src=/,dst=/host,options=rbind", "--privileged"]
      }
    }"""


    if is_fake():
      raise unittest.SkipTest('Test is not hermetic and should be skipped in fakes.')

    os.makedirs("/home/containerd", exist_ok=True)
    os.makedirs("/run/containerd", exist_ok=True)


    # The container expects these paths to exist.
    expected_paths = [
      "/run/containerd/runsc/config.toml",
      "/home/containerd/opt/containerd/bin/containerd-shim-runsc-v1",
      "/home/containerd/usr/local/bin/containerd-shim-runsc-v1",
      "/home/containerd/usr/local/sbin/runsc",
    ]

    for p in expected_paths:
      if os.path.exists(p):
        os.remove(p)
      self.assertFalse(os.path.exists(p))

    content = json.loads(gvisor_content)
    cont = installable.parse_installable(content)
    if cont.is_preloaded():
      installable.ctr.delete(cont.get_url())

    with self.assertLogs(logger=installable.LOGGER, level=logging.INFO) as logs:
      installable.process_installable(installable=cont, download=True)

    self.assertEqual(logs.output ,[
   'INFO:installable:Installable not preloaded...downloading',
   'INFO:installable:Running container '
   'gcr.io/gke-release-staging/gke-gvisor-installer@sha256:0c3e3ac8b7bfad7db5df9fe3c3d67eff11ce33ed4391a6ce323a5fced0ccef33 '
   'succeeded.'])


    for p in expected_paths:
      self.assertTrue(os.path.exists(p))
      os.remove(p)

  def test_cilium_cni_integration(self):
    if is_fake():
      raise unittest.SkipTest('Test is not hermetic and should be skipped in fakes.')

    # The container expects these paths to exist.
    os.makedirs('/home/kubernetes/bin', exist_ok=True)
    expected_paths = [
      "/home/kubernetes/bin/cilium-cni",
    ]

    for p in expected_paths:
      if os.path.exists(p):
        os.remove(p)
      self.assertFalse(os.path.exists(p))

    cilium_content = """{
      "kind":"Container",
      "apiVersion": "installable.gke.io/v1",
      "metadata":{
        "name":"cilium-cni"
      },
      "os":"linux",
      "arch":"MULTI",
      "version":"v1.15.6-gke.37",
      "remoteURL":"us.gcr.io/gke-release-staging/cilium/cilium:v1.15.6-gke.37",
      "digest":"d285cf77f04947eb3a81bf29362bc6c46e296831ea4d410bf7dc86149295890e",
      "digestAlgo":"sha256",
      "run": {
        "ctrArgs":[
          "--mount",
          "type=bind,src=/home/kubernetes/bin,dst=/host/opt/cni/bin,options=rbind",
          "--env",
          "CNI_DIR=/host/opt/cni"
        ],
        "containerArgs": ["/install-plugin.sh"]
      }
    }"""

    cont = installable.parse_installable(json.loads(cilium_content))
    if cont.is_preloaded():
      installable.ctr.delete(cont.get_url())
    with self.assertLogs(logger=installable.LOGGER, level=logging.INFO) as logs:
      installable.process_installable(installable=cont, download=True)


    self.assertEqual(logs.output, [
    'INFO:installable:Installable not preloaded...downloading',
    'INFO:installable:Running container '
    'us.gcr.io/gke-release-staging/cilium/cilium:v1.15.6-gke.37@sha256:d285cf77f04947eb3a81bf29362bc6c46e296831ea4d410bf7dc86149295890e '
    'succeeded.'])

    for p in expected_paths:
      self.assertTrue(os.path.exists(p))
      os.remove(p)

class InstallableTests(unittest.TestCase):

  def test_invalid_api(self):
    """Tests an apppkg with an invalid API raises an error."""
    content = """{"kind":"Container",
	"apiVersion": "unsupported-api",
	"metadata":{"name":"my-apppkg"}}"""
    with self.assertRaisesRegex(installable.InvalidInstallableError, 'Unknown api version'):
      with installable.parse_installable(json.loads(content)):
        pass

  def test_apppkg_not_supported(self):
    """Tests that apppkg is not a supported kind."""
    content = """{"kind":"AppPkg",
	"apiVersion": "installable.gke.io/v1",
	"metadata":{"name":"my-apppkg"}}"""
    with self.assertRaisesRegex(installable.InvalidInstallableError, 'Kind AppPkg is not supported for now'):
      with installable.parse_installable(json.loads(content)):
        pass

  def test_invalid_kind(self):
    """Tests an invalid kind raises an error."""
    content = """{"kind":"invalid kind",
	"apiVersion": "installable.gke.io/v1",
	"metadata":{"name":"my-apppkg"}}"""
    with self.assertRaisesRegex(installable.InvalidInstallableError, 'Unknown installable type'):
      installable.parse_installable(json.loads(content))

  def test_get_credentials(self):
    """Tests that some string is returned when we get credentials."""
    self.assertNotEqual(installable.get_gce_credentials(), "")

  def test_missing_fields(self):
    """Tests installables where required fields are missing."""
    spec = json.loads(container_content)
    del spec['remoteURL']
    with self.assertRaisesRegex(installable.InvalidInstallableError, 'remoteURL.*is omitted or emtpy'):
      installable.parse_installable(spec)

    spec = json.loads(container_content)
    spec['digestAlgo'] = ''
    d = ''
    with self.assertRaisesRegex(installable.InvalidInstallableError, 'digestAlgo.*is omitted or emtpy'):
      with installable.parse_installable(spec) as inst:
        d = inst.dir
    self.assertFalse(os.path.exists(d))

class CtrTests(unittest.TestCase):
  """
  CtrTests model supported arguments for installable container types.

  If you are adding support for a new argument for installable container types, you should add a
  test here. The cri interface that ctr interacts with is unstable, so we want to model required
  arguments here. In general, you should only need to mount host directories in the container
  and pass environment variables. Container installables should not download anything, just dump
  binaries and write configuration files on disk.
  """

  # We need a container image that has bash to run these test. This image rarely changes.
  bash_image = "gcr.io/gke-release-staging/gke-distroless/bash:gke_distroless_20241207.00_p0@sha256:9bd9f35657b03f55a00a33feac0500ee183dcfd5f7f1982cd35a7a032953d466"
  alpine_image = "docker.io/library/alpine@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c"

  def setUp(self):
    super().setUp()
    if is_fake():
      self.skipTest('CTR tests are not hermetic and require containerd.')
    installable.ctr.download(self.bash_image)

  def tearDown(self):
    super().setUp()
    if not is_fake():
      installable.ctr.delete(self.bash_image)

  def test_ctr_with_mount(self):
    """Tests that a ctr with the root directory mounted allows us to read from and write to it."""
    host_content = 'file on the host'
    guest_content = ' written by guest'
    host_file = ''
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as t:
      host_file = t.name
      t.write(host_content)

    os.chmod(path=host_file, mode=0o666)

    result = installable.ctr.run(
      container_name='mount_container',
      url=self.bash_image,
      ctr_args=[
        '--privileged',
        '--mount',
        'type=bind,src=/,dst=/host,options=rbind',
        ],
      container_args=[
        '/bin/sh',
        '-c',
        f'cat /host{host_file} && echo "{guest_content}" >> /host{host_file}'
      ],
    )

    self.assertEqual(result.returncode, 0, msg=result)
    self.assertEqual(host_content, result.stdout.decode('utf-8'))

    with open(host_file) as f:
      expected = host_content + guest_content
      self.assertEqual(f.read(len(expected)), expected)
    os.remove(host_file)


  def test_ctr_with_env_var(self):
    """Tests that a ctr passes environment variables."""
    env_var = 'MY_ENV'
    env_var_val = 'MY_VAL'
    result = installable.ctr.run(
      container_name='mount_container',
      url=self.bash_image,
      ctr_args=[
        '--env', f'{env_var}={env_var_val}'
        ],
      container_args=[
        '/bin/sh',
        '-c',
        f'echo ${env_var}'
      ],
    )
    self.assertEqual(result.returncode, 0, msg=result)
    self.assertEqual(env_var_val + '\n', result.stdout.decode('utf-8'))

fake_creds = "fake_creds"

def is_fake():
  return installable.get_gce_credentials() == fake_creds

if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('--fake', action='store_true', default=False)
  options, args = parser.parse_known_args()
  installable.ctr = installable.Ctr(container_run_output=False)
  if options.fake:
    installable.ctr = FakeCtr()
    def fake_get_creds() -> str:
      return fake_creds
    installable.get_gce_credentials = fake_get_creds

  unit_argv = sys.argv[:1] + args
  unittest.main(argv=unit_argv)

  # The tests above create a lot of temporary directories. Ensure they are cleaned up.
  for dir in os.listdir(tempfile.gettempdir()):
    assert not dir.startswith(tempfile.gettempprefix)
