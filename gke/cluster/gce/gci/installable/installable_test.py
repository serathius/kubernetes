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


def make_namespace(content: str, download: bool=False, output: str='', preload_file: str='') -> argparse.Namespace:
    """Makes a namespace similar to argparse.parse_args."""
    args = []
    if download:
      args.append('--download')
    if output:
      args.extend(['--output', output])
    if preload_file:
      args.extend(['--preload-file', preload_file])
    args.extend(['--installable', content])
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
	"run": {
		"ctrArgs" : ["--rm"],
		"containerArgs": ["/bin/sh", "-c", "echo hello"]
  }
}"""

garbage = 'this_is_garbage'

class FakeCtr(installable.Ctr):
  """FakeCtr fakes calls to the ctr executable."""
  images = {}

  def download(self, url: str) -> subprocess.CompletedProcess:
    if garbage in url:
      return subprocess.CalledProcessError(cmd="", returncode=255, stderr="This was a failed download.")
    self.images[url] = True
    return subprocess.CompletedProcess(args="", returncode=0)

  def run(self, name: str, url: str, ctr_args: str, container_args: str):
    if not url in self.images.keys():
      raise subprocess.CalledProcessError(cmd="", returncode=1, stderr="Image not on machine")
    return

  def list_images(self) -> subprocess.CompletedProcess:
    images = []
    for image in self.images.keys():
      images.append(image)
    out = subprocess.CompletedProcess(args="", returncode=0)
    out.stdout = ",".join(images)
    return out

  def delete(self, url: str):
    if not url in self.images.keys():
      return subprocess.CalledProcessError(cmd="", returncode=1, stderr="no image found")
    self.images.pop(url)


class ContainerTests(unittest.TestCase):
  """ContainerTests are tests for the "container" kind."""

  def test_parse(self):
    """Tests that a given container blob parses into a container object."""
    args = make_namespace(content=container_content)
    inst = installable.parse_installable(args)
    self.assertTrue(isinstance(inst, installable.Container))
    self.assertEqual(inst.get_name(), 'my-container')

  def test_download(self):
    """Tests the download function of the container."""
    args = make_namespace(content=container_content, download=True)
    container = installable.parse_installable(args)
    installable.ctr.delete(container.get_url())
    container.download()
    container.check_preloaded()
    installable.ctr.delete(container.get_url())

  def test_bad_url(self):
    """Tests that downloads fail given a bad URL."""
    content = json.loads(container_content)
    content['remoteURL'] = garbage
    args = make_namespace(content=json.dumps(content), download=True)
    with self.assertRaisesRegex(ValueError, 'Failed to download container'):
      inst = installable.parse_installable(args)
      inst.download()

  def test_install_with_preload(self):
    """Tests the base case for containers where we download the container and then run it with the given args."""
    args = make_namespace(content=container_content, download=True)
    container = installable.parse_installable(args)
    installable.ctr.delete(container.get_url())
    with self.assertRaises(ValueError):
      container.check_preloaded()
    with self.assertLogs(logger=installable.LOGGER, level=logging.INFO) as logs:
      installable.do_install(args)
    self.assertEqual(logs.output, ['INFO:installable:Processing installable: "my-container": url: '
    '"gcr.io/gke-release-staging/busybox@sha256:d8d3bc2c183ed2f9f10e7258f84971202325ee6011ba137112e01e30f206de67"'])
    installable.ctr.delete(container.get_url())

  def test_install_without_preload(self):
    """Tests the case where run the container without downloading it."""
    args = make_namespace(content=container_content, download=True)
    container = installable.parse_installable(args)
    faker = None
    # To setup, we need to download the container.
    container.download()
    container.check_preloaded()
    args = make_namespace(content=container_content, download=False)
    with self.assertLogs(logger=installable.LOGGER, level=logging.INFO) as logs:
      installable.do_install(args)
    self.assertEqual(logs.output, ['INFO:installable:Processing installable: "my-container": url: '
   '"gcr.io/gke-release-staging/busybox@sha256:d8d3bc2c183ed2f9f10e7258f84971202325ee6011ba137112e01e30f206de67"',
   'INFO:installable:Skip downloading on Container "my-container" as it should be preloaded'])
    container.check_preloaded()
    installable.ctr.delete(container.get_url())

  def test_install_container_without_preload_error(self):
    """Tests the case where we try to run a container that is not present."""
    args = make_namespace(content=container_content, download=False)
    container = installable.parse_installable(args)
    installable.ctr.delete(container.get_url())
    with self.assertRaises(ValueError):
      with self.assertLogs(logger=installable.LOGGER, level=logging.INFO) as logs:
        installable.do_install(args)
    self.assertEqual(logs.output, ['INFO:installable:Processing installable: "my-container": url: '
   '"gcr.io/gke-release-staging/busybox@sha256:d8d3bc2c183ed2f9f10e7258f84971202325ee6011ba137112e01e30f206de67"',
   'INFO:installable:Skip downloading on Container "my-container" as it should be preloaded'])
    with self.assertRaisesRegex(ValueError, 'Failed to find container'):
      container.check_preloaded()
    installable.ctr.delete(container.get_url())

apppkg_content = """{
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
	"digestAlgo":"SHA512",
	"fileMap": [
		{
			"source": "bridge",
			"dest": "bin/bridge",
			"mode": "644"
		}
	]
}"""

crictl_apppkg_content = """{
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

  def unwrap(self, file_path: str, dir_path: str, prefix: str, file_map: Any):
    for f in file_map:
      dest = f['dest']
      dest = os.path.join(prefix, dest)
      os.makedirs(os.path.dirname(dest), exist_ok=True)
      mode = f['mode']
      with open(dest, 'w+') as f:
        f.write('some content')
      os.chmod(dest, int(mode, 8))


class AppPkgTests(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    """Setup involves us generating a preload file used similarly to the "record-preload-info" and
    "is-preloaded" functions in configure.sh."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
      cls.preload_file = f.name

  @classmethod
  def tearDownClass(cls):
    """Simply delete the preload file on teardown."""
    if os.path.exists(cls.preload_file):
      os.remove(cls.preload_file)

  def test_parse_appkg(self):
    """Test that a valid apppkg parses and returns a valid apppkg."""
    args = make_namespace(content=apppkg_content, preload_file=self.preload_file)
    with installable.parse_installable(args) as inst:
      self.assertTrue(isinstance(inst, installable.AppPkg))
      self.assertEqual(inst.get_name(), "cni")

  def test_bad_url(self):
    """Checks that a bad URL fails to download."""
    content = json.loads(apppkg_content)
    content['remoteURL'] = garbage
    args = make_namespace(content=json.dumps(content), download=True, preload_file=self.preload_file)
    with self.assertRaisesRegex(urllib3.exceptions.MaxRetryError, 'Name or service not known'):
      with installable.parse_installable(args) as inst:
        inst.retry = 1
        inst.download()
    self.assertFalse(os.path.exists(inst.file))
    self.assertFalse(os.path.exists(inst.dir))

  def test_download(self):
    """Test download function."""
    args = make_namespace(content=apppkg_content, download=True, preload_file=self.preload_file)
    with installable.parse_installable(args) as inst:
      self._set_preload_file({inst.get_name(): inst._get_digest()})
      self.assertFalse(os.path.exists(inst.file))
      inst.download()
      self.assertTrue(os.path.exists(inst.file))
      algo = inst.content['digestAlgo']
      digest = inst.content['digest']
      installable.handler.checksum(file_path=inst.file, algo=algo, digest=digest)
    self.assertFalse(os.path.exists(inst.file))
    self.assertFalse(os.path.exists(inst.dir))

  def test_bad_preload_file(self):
    """Tests the case when the given preload file doesn't exist."""
    with tempfile.NamedTemporaryFile(delete=True) as f:
        file = f.name
    args = make_namespace(content=apppkg_content, download=True, preload_file=file)
    with self.assertRaisesRegex(ValueError, 'Invalid preload file:'):
      with installable.parse_installable(args) as inst:
        inst.retry = 1
        inst.download()

  def test_no_digest_in_preload_file(self):
    """Tests the case where the installable is not marked as preloaded in the file."""
    self._set_preload_file({})
    args = make_namespace(content=apppkg_content, download=False, preload_file=self.preload_file)
    with self.assertRaisesRegex(AssertionError, 'Could not find entry'):
      installable.do_install(args)

  def test_no_download_install(self):
    """Tests that installation path passes wihout downloading the file."""
    with tempfile.NamedTemporaryFile(delete=True) as f:
      file_name=f.name
    content = json.loads(apppkg_content)
    self._set_preload_file({content['metadata']['name']: content['digest']})
    args = make_namespace(content=apppkg_content, download=False, output=file_name, preload_file=self.preload_file)
    with self.assertLogs(installable.LOGGER, level=logging.INFO) as logs:
      installable.do_install(args)
    self.assertEqual(logs.output, [
      'INFO:installable:Processing installable: "cni": url: "https://storage.googleapis.com/gke-release/cni-plugins/v1.4.0-gke.3/cni-plugins-linux-amd64-v1.4.0-gke.3.tgz"',
      'INFO:installable:Skip downloading on AppPgk "cni" as it should be preloaded',
      'INFO:installable:Skip installing AppPkg "cni" as it should be preloaded',
      ])
    self.assertFalse(file_name == '' or os.path.exists(file_name))

  def test_download_install_dest(self):
    """Tests the case where we download the apppkg and put the downloaded artifact in a path of the user's choosing."""
    out_file = ''
    with tempfile.NamedTemporaryFile(delete=True) as f:
      out_file = f.name
    spec = json.loads(apppkg_content)
    del spec['fileMap']
    self._set_preload_file({})
    args = make_namespace(json.dumps(spec), download=True, output=out_file, preload_file=self.preload_file)
    self.assertFalse(os.path.exists(out_file))
    with self.assertLogs(installable.LOGGER, logging.INFO) as logs:
      installable.do_install(args)
    for log in logs.output:
      self.assertFalse(credentials_in_log(log))
    self.assertTrue(os.path.exists(out_file))
    with installable.parse_installable(args) as inst:
      installable.handler.checksum(file_path=out_file, algo=spec['digestAlgo'], digest=spec['digest'])
    os.remove(out_file)

  def test_download_install_unwrap(self):
    """Tests the case where we download the apppkg, unwrap it, and place specified binaries in given paths."""
    spec = json.loads(apppkg_content)
    self._set_preload_file({})
    with tempfile.TemporaryDirectory() as d:
      spec['installPrefix'] = d
      args = make_namespace(json.dumps(spec), download=True, preload_file=self.preload_file)
      with self.assertLogs(installable.LOGGER, level=logging.INFO) as logs:
        installable.do_install(args)
      for log in logs.output:
        self.assertFalse(credentials_in_log(log))
      for file in spec['fileMap']:
        dest_path = os.path.join(d, file['dest'])
        self.assertTrue(os.path.exists(dest_path))
        mode = int(file['mode'], 8)
        st = os.stat(dest_path)
        got_mode = st.st_mode & 0o777
        self.assertEqual(oct(mode), oct(got_mode))


  def test_crictl_case(self):
    """Tests downloading a different apppkg: crictl."""
    out_file = ''
    with tempfile.NamedTemporaryFile(delete=True) as f:
      out_file = f.name
    spec = json.loads(crictl_apppkg_content)
    self._set_preload_file({spec['metadata']['name']: spec['digest']})
    args = make_namespace(
      json.dumps(spec), download=True, output=out_file, preload_file=self.preload_file)
    self.assertFalse(os.path.exists(out_file))
    installable.do_install(args)
    self.assertTrue(os.path.exists(out_file))
    with installable.parse_installable(args) as inst:
      installable.handler.checksum(file_path=out_file, algo=spec['digestAlgo'], digest=spec['digest'])
    os.remove(out_file)

  def _set_preload_file(self, info: dict):
    """Sets the preload file content. Utility method for the tests."""
    with open(self.preload_file, 'w+') as f:
      f.write('something,some_digest\n')
      for name in info.keys():
        digest = info[name]
        f.write(f'{name},{digest}\n')

class InstallableTests(unittest.TestCase):

  def test_invalid_api(self):
    """Tests an apppkg with an invalid API raises an error."""
    content = """{"kind":"AppPkg",
	"apiVersion": "unsupported-api",
	"metadata":{"name":"my-apppkg"}}"""
    args = make_namespace(content=content)
    with self.assertRaisesRegex(ValueError, 'Unknown api version'):
      with installable.parse_installable(args):
        pass

  def test_invalid_kind(self):
    """Tests an invalid kind raises an error."""
    content = """{"kind":"invalid kind",
	"apiVersion": "installable.gke.io/v1",
	"metadata":{"name":"my-apppkg"}}"""
    args = make_namespace(content=content)
    with self.assertRaisesRegex(ValueError, 'Unknown installable type'):
      installable.parse_installable(args)

  def test_get_credentials(self):
    """Tests that some string is returned when we get credentials."""
    self.assertNotEqual(installable.get_gce_credentials(), "")

  def test_missing_fields(self):
    """Tests installables where required fields are missing."""
    spec = json.loads(container_content)
    del spec['remoteURL']
    args = make_namespace(content=json.dumps(spec))
    with self.assertRaisesRegex(ValueError, 'remoteURL.*is omitted or emtpy'):
      installable.parse_installable(args)

    spec = json.loads(apppkg_content)
    spec['digestAlgo'] = ''
    args = make_namespace(content=json.dumps(spec))
    d = ''
    with self.assertRaisesRegex(ValueError, 'digestAlgo.*is omitted or emtpy'):
      with installable.parse_installable(args) as inst:
        d = inst.dir
    self.assertFalse(os.path.exists(d))

if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('--fake', default=False)
  options, args = parser.parse_known_args()
  if options.fake:
    installable.ctr = FakeCtr()
    def fake_get_creds() -> str:
      return "fake creds"
    installable.get_gce_credentials = fake_get_creds
    installable.handler = FakeAppPkgHandler()

  unit_argv = sys.argv[:1] + args
  unittest.main(argv=unit_argv)

  # The tests above create a lot of temporary directories. Ensure they are cleaned up.
  for dir in os.listdir(tempfile.gettempdir()):
    assert not dir.startswith(tempfile.gettempprefix)



