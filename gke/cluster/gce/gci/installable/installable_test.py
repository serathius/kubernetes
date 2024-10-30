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
import urllib3


def make_namespace(content: str, no_download: str='False', output: str='', preload_file: str='', run: bool=False) -> argparse.Namespace:
    """Makes a namespace similar to argparse.parse_args."""
    args = []
    if no_download:
      args.append(f'--no-download={no_download}')
    if output:
      args.extend(['--output', output])
    if preload_file:
      args.extend(['--preload-file', preload_file])
    args.extend(['--installable', content])
    if run:
      args.append(f'--run={str(run)}')
    return installable.parser.parse_args(args)

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
	"remoteURL":"gcr.io/gke-release-staging/busybox",
	"digest":"d8d3bc2c183ed2f9f10e7258f84971202325ee6011ba137112e01e30f206de67",
	"digestAlgo":"sha256",
	"containerArgs":["echo", "hello"]
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
    args = make_namespace(content=container_content)
    container = installable.parse_installable(args)
    if container.is_preloaded():
      installable.ctr.delete(container.get_url())
    if isinstance(installable.ctr, FakeCtr):
      installable.ctr.images = {}

  def test_parse(self):
    """Tests that a given container blob parses into a container object."""
    args = make_namespace(content=container_content)
    inst = installable.parse_installable(args)
    self.assertTrue(isinstance(inst, installable.Container))
    self.assertEqual(inst.name(), 'my-container')

  def test_download(self):
    """Tests the download function of the container."""
    args = make_namespace(content=container_content, no_download='false', run=True)
    container = installable.parse_installable(args)
    with self.assertLogs(logger=installable.LOGGER, level=logging.INFO) as logs:
      installable.process_installable(args)
    self.assertEqual(logs.output, ['INFO:installable:Processing installable: "my-container": url: '
   '"gcr.io/gke-release-staging/busybox@sha256:d8d3bc2c183ed2f9f10e7258f84971202325ee6011ba137112e01e30f206de67"',
   'INFO:installable:Installable not preloaded...downloading',
   'INFO:installable:Running container '
   'gcr.io/gke-release-staging/busybox@sha256:d8d3bc2c183ed2f9f10e7258f84971202325ee6011ba137112e01e30f206de67 '
   'succeeded.'])
    self.assertTrue(container.is_preloaded())

  def test_download_ignore_preload_file(self):
    """Tests the download function of the container."""
    preload_file = 'should_not_exist'
    self.assertFalse(os.path.exists(preload_file))
    args = make_namespace(content=container_content, no_download='False', preload_file=preload_file)
    container = installable.parse_installable(args)
    self.assertFalse(container.is_preloaded())
    with self.assertLogs(logger=installable.LOGGER, level=logging.INFO) as logs:
      installable.process_installable(args)
    self.assertEqual(logs.output, ['INFO:installable:Processing installable: "my-container": url: '
   '"gcr.io/gke-release-staging/busybox@sha256:d8d3bc2c183ed2f9f10e7258f84971202325ee6011ba137112e01e30f206de67"',
   'INFO:installable:Installable not preloaded...downloading'])
    self.assertFalse(os.path.exists(preload_file))
    self.assertTrue(container.is_preloaded())

  def test_download_ignore_output_file(self):
    """Tests the download function of the container."""
    output_file = 'should_not_exist'
    self.assertFalse(os.path.exists(output_file))
    args = make_namespace(content=container_content, no_download='false', output=output_file)
    container = installable.parse_installable(args)
    self.assertFalse(container.is_preloaded())
    with self.assertLogs(logger=installable.LOGGER, level=logging.INFO) as logs:
      installable.process_installable(args)
    self.assertEqual(logs.output, ['INFO:installable:Processing installable: "my-container": url: '
   '"gcr.io/gke-release-staging/busybox@sha256:d8d3bc2c183ed2f9f10e7258f84971202325ee6011ba137112e01e30f206de67"',
   'INFO:installable:Installable not preloaded...downloading'])
    self.assertFalse(os.path.exists(output_file))
    self.assertTrue(container.is_preloaded())

  def test_bad_url(self):
    """Tests that downloads fail given a bad URL."""
    content = json.loads(container_content)
    content['remoteURL'] = garbage
    args = make_namespace(content=json.dumps(content), no_download='False')
    with self.assertRaisesRegex(installable.DownloadError, 'Failed to download container'):
      inst = installable.parse_installable(args)
      inst.download()

  def test_already_preloaded(self):
    args = make_namespace(content=container_content, no_download='true', run='True')
    container = installable.parse_installable(args)
    installable.ctr.download(container.get_url())
    self.assertTrue(container.is_preloaded())
    with self.assertLogs(logger=installable.LOGGER, level=logging.INFO) as logs:
      installable.process_installable(args)
    self.assertEqual(logs.output, ['INFO:installable:Processing installable: "my-container": url: '
   '"gcr.io/gke-release-staging/busybox@sha256:d8d3bc2c183ed2f9f10e7258f84971202325ee6011ba137112e01e30f206de67"',
   'INFO:installable:Running container '
   'gcr.io/gke-release-staging/busybox@sha256:d8d3bc2c183ed2f9f10e7258f84971202325ee6011ba137112e01e30f206de67 '
   'succeeded.'])


  def test_not_preloaded(self):
    args = make_namespace(content=container_content, no_download='True')
    container = installable.parse_installable(args)
    self.assertFalse(container.is_preloaded())
    with self.assertLogs(logger=installable.LOGGER, level=logging.INFO) as logs:
      with self.assertRaisesRegex(installable.PreloadError, f'Installable {container.name()} not preloaded.'):
        installable.process_installable(args)
    self.assertEqual(logs.output, ['INFO:installable:Processing installable: "my-container": url: '
   '"gcr.io/gke-release-staging/busybox@sha256:d8d3bc2c183ed2f9f10e7258f84971202325ee6011ba137112e01e30f206de67"'])
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
      "ctrArgs":["--rm", "--mount", "type=bind,src=/,dst=/host,options=rbind", "--privileged"]
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

    args = make_namespace(content=gvisor_content, run=True)
    cont = installable.parse_installable(args)
    if cont.is_preloaded():
      installable.ctr.delete(cont.get_url())

    with self.assertLogs(logger=installable.LOGGER, level=logging.INFO) as logs:
      installable.process_installable(args)

    self.assertEqual(logs.output ,['INFO:installable:Processing installable: "gvisor": url: '
   '"gcr.io/gke-release-staging/gke-gvisor-installer@sha256:0c3e3ac8b7bfad7db5df9fe3c3d67eff11ce33ed4391a6ce323a5fced0ccef33"',
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
      "ctrArgs":[
        "--mount",
       "type=bind,src=/home/kubernetes/bin,dst=/host/opt/cni/bin,options=rbind",
       "--env",
       "CNI_DIR=/host/opt/cni"
      ],
      "containerArgs": ["/install-plugin.sh"]
    }"""

    args = make_namespace(content=cilium_content, run=True)
    cont = installable.parse_installable(args)
    if cont.is_preloaded():
      installable.ctr.delete(cont.get_url())
    with self.assertLogs(logger=installable.LOGGER, level=logging.INFO) as logs:
      installable.process_installable(args)


    self.assertEqual(logs.output, ['INFO:installable:Processing installable: "cilium-cni": url: '
    '"us.gcr.io/gke-release-staging/cilium/cilium:v1.15.6-gke.37@sha256:d285cf77f04947eb3a81bf29362bc6c46e296831ea4d410bf7dc86149295890e"',
    'INFO:installable:Installable not preloaded...downloading',
    'INFO:installable:Running container '
    'us.gcr.io/gke-release-staging/cilium/cilium:v1.15.6-gke.37@sha256:d285cf77f04947eb3a81bf29362bc6c46e296831ea4d410bf7dc86149295890e '
    'succeeded.'])

    for p in expected_paths:
      self.assertTrue(os.path.exists(p))
      os.remove(p)


app_pkg_content = """{
	"kind":"AppPkg",
	"apiVersion": "installable.gke.io/v1",
	"metadata":{
	  "name":"cni"
	},
	"os":"linux",
	"arch":"X86_64",
	"version":"v1.4.0-gke.3",
	"remoteURL":"https://storage.googleapis.com/gke-release/cni-plugins/v1.4.0-gke.3/cni-plugins-linux-amd64-v1.4.0-gke.3.tgz",
	"digest":"44a461d6446ce82f9f4b8e81fd95c7b86ca1c4e4c34825b8a1dc0533073e0655750c4b9d39d7d2b742eb0146e0ee9265351d5f04b8e04e953d5cf8fefce33cf9",
	"digestAlgo":"SHA512"
}"""

crictl_app_pkg_content = """{
	"kind":"AppPkg",
	"apiVersion": "installable.gke.io/v1",
	"metadata":{
	  "name":"crictl"
	},
	"os":"linux",
	"arch":"X86_64",
	"version": "v1.28.0-gke.1",
  "remoteURL": "https://storage.googleapis.com/gke-release/cri-tools/v1.28.0-gke.1/crictl-v1.28.0-gke.1-linux-amd64.tar.gz",
  "digest":"46387d29d2d79efe0fc0b83df3de6f3d9b00d1477d9765cd8e9a5d30b234d6d9b5bfd408bf4f7741c75a7bc0163b362156475e941c6387476866f0e69bae6ce3",
  "digestAlgo":"SHA512"
}"""

class FakeAppPkgHandler(installable.AppPkgHandler):
  '''FakeAppPkgHanlder fakes installable.AppPkgHandler methods.'''

  def download(self, retry: int, url: str) -> bytes:
    if url == garbage:
      raise urllib3.exceptions.MaxRetryError(url=url, pool=None, reason='Name or service not known')
    return b'some bytes to write'

  def checksum(self, file_path: str, algo: str, digest: str):
    if digest == garbage:
      raise ValueError(f'mismatch digest: got: {garbage} want: "some valid digest"')

class AppPkgTests(unittest.TestCase):

  preload_file = ''
  output_file = ''

  def setUp(self):
    """Setup involves us generating a preload file used similarly to the "record-preload-info" and
    "is-preloaded" functions in configure.sh."""
    super().setUp()
    for file in [self.preload_file, self.output_file]:
      if os.path.exists(file):
        os.remove(file)
    with tempfile.NamedTemporaryFile(delete=False) as f:
      self.preload_file = f.name
    with tempfile.NamedTemporaryFile(delete=True) as f:
      self.output_file = f.name

  def test_parse(self):
    """Test that a valid apppkg parses and returns a valid apppkg."""
    args = make_namespace(content=app_pkg_content, output=self.output_file, preload_file=self.preload_file)
    with installable.parse_installable(args) as inst:
      self.assertTrue(isinstance(inst, installable.AppPkg))
      self.assertEqual(inst.name(), "cni")

  def test_download(self):
    """Test download function."""
    args = make_namespace(content=app_pkg_content, no_download="false",
                          output=self.output_file, preload_file=self.preload_file, run=True)
    with installable.parse_installable(args) as inst:
      self._set_preload_file(info={})
      self.assertFalse(os.path.exists(self.output_file))
      with self.assertLogs(logger=installable.LOGGER, level=logging.INFO) as logs:
        installable.process_installable(args)
      self.assertEqual(logs.output, ['INFO:installable:Processing installable: "cni": url: '
      '"https://storage.googleapis.com/gke-release/cni-plugins/v1.4.0-gke.3/cni-plugins-linux-amd64-v1.4.0-gke.3.tgz"',
      'INFO:installable:Installable not preloaded...downloading',
      'INFO:installable:AppPkg types do not have a run method. Returning.'])
      self.assertTrue(os.path.exists(self.output_file))
      self.assertTrue(inst.is_preloaded())
      algo = inst.content['digestAlgo']
      digest = inst.content['digest']
      installable.handler.checksum(file_path=self.output_file, algo=algo, digest=digest)

  def test_bad_preload_file(self):
    """Tests the case when the given preload file doesn't exist."""
    with tempfile.NamedTemporaryFile(delete=True) as f:
        file = f.name
    args = make_namespace(content=app_pkg_content, no_download="False", preload_file=file)
    with self.assertRaisesRegex(argparse.ArgumentTypeError, 'Invalid preload file:'):
      with installable.parse_installable(args) as inst:
        inst.retry = 1
        inst.download()

  def test_no_output_target_provided(self):
    args = make_namespace(content=app_pkg_content, no_download="false", preload_file=self.preload_file)
    with self.assertRaisesRegex(argparse.ArgumentTypeError, 'Output file path is required for AppPkg installables.'):
      installable.process_installable(args)

  def test_bad_url(self):
    """Checks that a bad URL fails to download."""
    content = json.loads(app_pkg_content)
    content['remoteURL'] = garbage
    args = make_namespace(content=json.dumps(content), no_download="False",
                          output=self.output_file, preload_file=self.preload_file)
    with self.assertRaisesRegex(urllib3.exceptions.MaxRetryError, 'Name or service not known'):
      with installable.parse_installable(args) as inst:
        inst.retry = 1
        inst.download()
    self.assertFalse(os.path.exists(self.output_file))

  def test_already_preloaded(self):
    args = make_namespace(content=app_pkg_content, no_download='true',
                          output=self.output_file, preload_file=self.preload_file)
    app_pkg = installable.parse_installable(args)
    self._set_preload_file([f'{app_pkg.name()},{app_pkg.digest()}'])
    self.assertTrue(app_pkg.is_preloaded())
    with self.assertLogs(logger=installable.LOGGER, level=logging.INFO) as logs:
      installable.process_installable(args)
    self.assertEqual(logs.output, ['INFO:installable:Processing installable: "cni": url: '
      '"https://storage.googleapis.com/gke-release/cni-plugins/v1.4.0-gke.3/cni-plugins-linux-amd64-v1.4.0-gke.3.tgz"'])

  def test_not_preloaded(self):
    args = make_namespace(content=crictl_app_pkg_content, no_download='TRUE',
                          output=self.output_file, preload_file=self.preload_file)
    crictl = installable.parse_installable(args)
    self.assertFalse(crictl.is_preloaded())
    with self.assertLogs(logger=installable.LOGGER, level=logging.INFO) as logs:
      with self.assertRaisesRegex(installable.PreloadError, f'Installable {crictl.name()} not preloaded.'):
        installable.process_installable(args)
    self.assertEqual(logs.output, ['INFO:installable:Processing installable: "crictl": url: '
      '"https://storage.googleapis.com/gke-release/cri-tools/v1.28.0-gke.1/crictl-v1.28.0-gke.1-linux-amd64.tar.gz"'])
    self.assertFalse(crictl.is_preloaded())

  def test_crictl_case(self):
    """Tests downloading a different apppkg: crictl."""
    args = make_namespace(
      crictl_app_pkg_content, no_download="FALSE", output=self.output_file, preload_file=self.preload_file)
    self.assertFalse(os.path.exists(self.output_file))
    with self.assertLogs(installable.LOGGER, logging.INFO) as logs:
      installable.process_installable(args)
    self.assertTrue(os.path.exists(self.output_file))
    with installable.parse_installable(args) as inst:
      self.assertTrue(inst.is_preloaded())

  def _set_preload_file(self, info: list=[]):
    """Sets the preload file content. Utility method for the tests."""
    with open(self.preload_file, 'w+') as f:
      f.write('something,some_digest\n')
      content = '\n'.join(info)
      f.write(content)

class InstallableTests(unittest.TestCase):

  def test_invalid_api(self):
    """Tests an apppkg with an invalid API raises an error."""
    content = """{"kind":"AppPkg",
	"apiVersion": "unsupported-api",
	"metadata":{"name":"my-apppkg"}}"""
    args = make_namespace(content=content)
    with self.assertRaisesRegex(installable.InvalidInstallableError, 'Unknown api version'):
      with installable.parse_installable(args):
        pass

  def test_invalid_kind(self):
    """Tests an invalid kind raises an error."""
    content = """{"kind":"invalid kind",
	"apiVersion": "installable.gke.io/v1",
	"metadata":{"name":"my-apppkg"}}"""
    args = make_namespace(content=content)
    with self.assertRaisesRegex(installable.InvalidInstallableError, 'Unknown installable type'):
      installable.parse_installable(args)

  def test_get_credentials(self):
    """Tests that some string is returned when we get credentials."""
    self.assertNotEqual(installable.get_gce_credentials(), "")

  def test_missing_fields(self):
    """Tests installables where required fields are missing."""
    spec = json.loads(container_content)
    del spec['remoteURL']
    args = make_namespace(content=json.dumps(spec))
    with self.assertRaisesRegex(installable.InvalidInstallableError, 'remoteURL.*is omitted or emtpy'):
      installable.parse_installable(args)

    spec = json.loads(app_pkg_content)
    spec['digestAlgo'] = ''
    args = make_namespace(content=json.dumps(spec))
    d = ''
    with self.assertRaisesRegex(installable.InvalidInstallableError, 'digestAlgo.*is omitted or emtpy'):
      with installable.parse_installable(args) as inst:
        d = inst.dir
    self.assertFalse(os.path.exists(d))

fake_creds = "fake_creds"

def is_fake():
  return installable.get_gce_credentials() == fake_creds

if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('--fake', default=False)
  options, args = parser.parse_known_args()
  if options.fake:
    installable.ctr = FakeCtr()
    def fake_get_creds() -> str:
      return fake_creds
    installable.get_gce_credentials = fake_get_creds
    installable.handler = FakeAppPkgHandler()

  unit_argv = sys.argv[:1] + args
  unittest.main(argv=unit_argv)

  # The tests above create a lot of temporary directories. Ensure they are cleaned up.
  for dir in os.listdir(tempfile.gettempdir()):
    assert not dir.startswith(tempfile.gettempprefix)



