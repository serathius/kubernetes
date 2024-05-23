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

"""Library for processing installables.

This module is for parsing 'installable' components, that is software
that is downloaded and installed at boot node boot time or preload time.
This is intended to work with internal GKE definitions for EVE, which
will manage installable versions internally. The module parses those
definitions and processes them to download and install the proper versions
of a give installable.

Installables can be of two types:
- AppPkgs are files stored in cloud storage. Usually these are archives that can be unwrapped
  with tar.
- Containers which are downloaded from the container registry.
"""

import argparse
import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List
import urllib3

parser = argparse.ArgumentParser()
parser.add_argument(
    '-i',
    '--installable',
    help='Installable object described as a JSON blob.',
    required=True,
    type=str,
)

parser.add_argument(
    '-o',
    '--output',
    help=(
      '''Absolute file to which to write AppPkg installables. If set, write the downloaded
      file to this directory. Ignored for containers.'''
    ),
    default='',
    nargs='?',
    type=str,
)

parser.add_argument(
  '-d',
  '--download',
  help=(
    '''If set, the script will download files. Useful when we are booting from a preloaded
    image. For containers, this means we only perform the run logic. For binaries, we
    return immediately without attempting to download or move files.'''
  ),
  default=False,
  action='store_true',
)

parser.add_argument(
  '-p',
  '--preload-file',
  help=(
    '''Path to file where preload info is recoreded. It is used to check if a given AppPkg is
    preloaded or not. Preload info for AppPkgs is also recorded in this file if we are preloading
    an AppPkg. Required for AppPkgs. See configure.sh: "is-preloaded" and "record-preload-info"
    functions.'''
  ),
  default='',
  nargs='?',
  type=str,
)

LOGGER = logging.getLogger(__name__)

def get_gce_credentials() -> str:
  """get_gce_credentials returns the credentials by querying the metadata server."""
  service_account_url = 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'
  retries = urllib3.util.Retry(
    total=5,
    backoff_factor=0.5,
  )
  timeout = urllib3.util.Timeout(connect=10.0)
  with urllib3.PoolManager(
    retries=retries,
    timeout=timeout,
  ) as http:
    response = http.request('GET', service_account_url, headers={'Metadata-Flavor': 'Google'})
    if response.status != 200:
      raise IOError(f'Failed to get credentials: status: {response.status} reason: {response.reason}')
    data = response.data.decode('utf-8')
    return json.loads(data)['access_token']

class Ctr:
  """Ctr is a wrapper around the container binary. It is used for faking in tests."""
  def download(self, url: str) -> subprocess.CompletedProcess:
    cmd = f'ctr -n k8s.io image pull --user="oauth2accesstoken:{get_gce_credentials()}" {url}'
    return subprocess.run(
      args=cmd,
      shell=True,
      capture_output=True,
    )

  def run(self, name: str, url: str, ctr_args: str, container_args: str):
    cmd = f'ctr -n k8s.io run --rm {ctr_args} {url} {name} {container_args}'
    subprocess.run(
      args=cmd,
      shell=True,
      check=True,
      capture_output=True,
    )

  def list_images(self) -> subprocess.CompletedProcess:
    cmd = 'ctr -n k8s.io images list'
    return subprocess.run(
      args=cmd,
      shell=True,
      capture_output=True,
    )

  def delete(url: str):
    cmd = f'ctr -n k8s.io images delete {url}'
    subprocess.run(
      args=cmd,
      shell=True,
      check=True,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
    )

ctr = Ctr()

class Installable:
  """Installable is the parent class for all installables."""

  def __init__(self, installable: Any, args: argparse.Namespace):
    if installable['metadata']['name'] == '':
      raise ValueError('Name must not be omitted.')
    for f in ['remoteURL', 'digestAlgo', 'digest']:
      if f not in installable or installable[f] == "":
        raise ValueError(f'Requred field "{f}" is omitted or emtpy')
    self.content = installable
    self.should_download = args.download

  def __enter__(self):
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    return

  def download(self):
    raise NotImplementedError()

  def check_preloaded(self):
    raise NotImplementedError()

  def install(self):
    raise NotImplementedError()

  def get_name(self) -> str:
    return self.content['metadata']['name']

  def get_url(self):
    raise NotImplementedError()

class Container(Installable):
  """A container kind installable.

  Container is an installable backed by a container. In this class, we use cri-tools to do
  operations like download and running the container.
  """

  def download(self):
    """Downloads the underlying container with ctr."""
    if not self.should_download:
      LOGGER.info(f'Skip downloading on Container "{self.get_name()}" as it should be preloaded')
      return
    out = ctr.download(self.get_url())
    if out.returncode != 0:
      msg = out.stderr.strip()
      raise ValueError(f'Failed to download container: return_code: {out.returncode} msg: {msg}')

  def check_preloaded(self):
    """Use ctr to search the machine to make sure this container is preloaded."""
    out = ctr.list_images()
    if out.returncode != 0:
      err = out.stderr.strip()
      raise ValueError(f'Failed to run ctr: exit_code: {out.returncode} error: {err}')

    stdout = str(out.stdout.strip())
    if self.get_url() not in stdout:
      raise ValueError(f'Failed to find container "{self.get_name()}" on disk: "{stdout}"')

  def install(self):
    """Install runs the container with the given arguments using ctr."""
    if self._should_run() is None:
      LOGGER.info(f'Run not requested on {self.get_name()}')
      return

    ctr_args = shlex.join(self.get_ctr_args())
    container_args = shlex.join(self.get_container_args())
    ctr.run(name=self.get_name(), url=self.get_url(),
                 ctr_args=ctr_args, container_args=container_args)

  def _should_run(self) -> Dict[str, Any]:
    """Check if we should run this container."""
    return self.content['run'] if 'run' in self.content else {}

  def get_url(self) -> str:
    """Return the URL string for this container"""

    # For containers, this is of the form: gcr.io/path/to/container@sha256:checksum_string.
    return '%s@%s:%s' % (
        self.content['remoteURL'],
        self.content['digestAlgo'],
        self.content['digest'],
    )

  def get_ctr_args(self) -> List[str]:
    """ctr args are args to ctr such as mounts and network specs"""
    run = self._should_run()
    return run['ctrArgs'] if run and 'ctrArgs' in run else []

  def get_container_args(self) -> List[str]:
    """container args are the actual arguments given to the container (e.g. /bin/sh echo hello)"""
    run = self._should_run()
    return run['containerArgs'] if run and 'containerArgs' in run else []


class AppPkg(Installable):
  """Class to handle the apppkg kind.

  AppPkgs are files that are downloaded from some storage location, usually a GCS bucket.
  AppPkgs have been the primary type of legacy component on GKE: e.g. cni plugin, crictl, etc.
  """

  def __init__(self, installable: Any, args: argparse.Namespace):
    super().__init__(installable, args)
    # The preload file marks if an apppkg has been preloaded yet. This is usually
    # /home/kubernetes/preload_info with entries of the form {name}:{checksum}.
    if not os.path.exists(args.preload_file):
      raise ValueError(f'Invalid preload file: "{args.preload_file}".')
    self.preload_file = args.preload_file
    self.output_file = args.output
    # Store a path to a temporary file in a temporary directory. We will use the file as a
    # target to download the package and the directory as a target to extract the needed files.
    self.dir = tempfile.mkdtemp()
    self.file = tempfile.mktemp(dir=self.dir)

  def __enter__(self):
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    if os.path.exists(self.dir):
      shutil.rmtree(self.dir)

  def download(self):
    """download function for apppkgs.

    Downloads an apppkg via urllib, validates the checksum, and records the apppkg as preloaded.
    """
    if not self.should_download:
      LOGGER.info(f'Skip downloading on AppPgk "{self.get_name()}" as it should be preloaded')
      return
    creds = get_gce_credentials()
    retry = self.retry if hasattr(self, 'retry') else 6
    retries = urllib3.util.Retry(
      total=retry,
      backoff_factor=1.0,
    )
    timeout = urllib3.util.Timeout(connect=20.0, read=10.0)
    with urllib3.PoolManager(
      retries=retries,
      timeout=timeout,
    ) as http:
      resp = http.request('GET', self.get_url(),
                              headers={'Authorization': f'Bearer {creds}'})
      if resp.status != 200:
        raise IOError(f'Failed to download AppPkg: status: {resp.status} reason: {resp.reason}')
      with open(self.file, '+wb') as f:
        f.write(resp.data)
      checksum = self.get_checksum(self.file, self.content['digestAlgo'])
      if checksum != self._get_digest():

        raise ValueError(
          f'Hash validation failed for AppPkg "{self.get_name()}": url: {self.get_url()} '
          f'got: {checksum} want: {self._get_digest()}'
        )
    self._record_preload_info()

  def check_preloaded(self):
    """For apppkgs, check preload checks the preload file for an entry for this apppkg. Similar to
      the 'is-preloaded' method in configure.sh"""
    with open(self.preload_file, 'r') as f:
      content = f.read()
      name = re.escape(self.get_name())
      digest = re.escape(self._get_digest())
    regex = re.compile(fr'{name},{digest}')
    if not regex.search(content):
      raise AssertionError(
        f'Could not find entry "{self.get_name()},{self._get_digest()} in preload file: {content}"'
      )

  def install(self):
    """Install for apppkgs copies the downloaded archive to a user given path or unwraps the archive
    and places it in user defined paths."""
    if not self.should_download:
      LOGGER.info(f'Skip installing AppPkg "{self.get_name()}" as it should be preloaded')
      return

    if self.output_file:
      shutil.copy2(src=self.file, dst=self.output_file)

    fileMap = self.content.get('fileMap', [])
    if fileMap:
      self._unwrap()
    prefix = self.content.get('installPrefix', '')
    for f in fileMap:
      source = f['source']
      dest = f['dest']
      mode = f['mode']
      source = os.path.join(self.dir, source)
      dest = os.path.join(prefix, dest)
      os.makedirs(os.path.dirname(dest), exist_ok=True)
      shutil.copyfile(source, dest)
      os.chmod(dest, int(mode, 8))

  def _record_preload_info(self):
    """records the preload info similar to the 'record-preload-info' function in configure.sh"""
    with open(self.preload_file, '+a') as f:
      f.write(f'{self.get_name()},{self._get_digest()}')

  def get_url(self) -> str:
    """AppPkg URLs are simply the given remoteURL."""
    return self.content['remoteURL'] if 'remoteURL' in self.content else ''

  def _get_digest(self) -> str:
    """Returns the digest for this apppkg."""
    return self.content['digest']

  @classmethod
  def get_checksum(_, file_path: str, algo: str) -> str:
    """get_checksum computes the checksum for validating downloaded AppPkgs."""
    func = getattr(hashlib, algo.lower())
    if func is None:
      raise ValueError('Unknown digest algo: %s' % algo)
    # we can choose different algos here as hashlib supports several.
    with open(file_path, mode='rb') as f:
      return func(f.read()).hexdigest()

  def _unwrap(self):
    """unwrap uses tar to unwrap the archive."""
    tar_cmd = f'tar -xzf {self.file} -C {self.dir}'
    subprocess.run(
      args=tar_cmd,
      shell=True,
      check=True,
      capture_output=True,
    )

def parse_installable(args: argparse.Namespace) -> Installable:
  """parse_installable parses the given json installable returns the correct class based on kind"""
  inst = json.loads(args.installable)
  if inst['apiVersion'] != 'installable.gke.io/v1':
    raise ValueError('Unknown api version: %s' % inst['apiVersion'])
  kind = inst['kind'].lower()
  if kind == 'container':
    return Container(inst, args)
  if kind == 'apppkg':
    return AppPkg(inst, args)
  raise ValueError(f'Unknown installable type: {kind}')

def do_install(args: argparse.Namespace):
  """do_install performs the sequence common to all installables."""
  with parse_installable(args) as inst:
    LOGGER.info(f'Processing installable: "{inst.get_name()}": url: "{inst.get_url()}"')
    inst.download()
    inst.check_preloaded()
    inst.install()

if __name__ == '__main__':
  do_install(parser.parse_args(sys.argv[1:]))