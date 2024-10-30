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

This module is for parsing 'installable' components, that is software/files
that are downloaded and installed at boot node boot time or preload time.
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
import subprocess
import sys
from typing import Any
import urllib3

LOGGER = logging.getLogger('installable')


parser = argparse.ArgumentParser()
parser.add_argument(
    '--installable',
    help='Installable object described as a JSON blob.',
    required=True,
    type=str,
)


parser.add_argument(
    '-d', '--debug',
    help="Print debug statements",
    action="store_const", dest="loglevel", const=logging.DEBUG,
    default=logging.WARNING,
)

parser.add_argument(
    '--output',
    help=(
      '''Absolute file to which to write AppPkg installables. Required for AppPkgs. Ignored for
      containers.'''
    ),
    default='',
    nargs='?',
    type=str,
)

def str_to_bool(v):
  if isinstance(v, bool):
    return v
  if v.lower() == 'true':
    return True
  if not v or v.lower() == 'false':
    return False
  raise argparse.ArgumentTypeError(f'Invalid arg: expected boolean got: {v}')


parser.add_argument(
  '--run',
  help=(
    '''If true, call the run method.'''
  ),
  default=False,
  type=str_to_bool,
)


parser.add_argument(
  '--no-download',
  help=(
    '''If true, we should not download files. This is to control booting from production'''
  ),
  default=False,
  type=str_to_bool,
)

parser.add_argument(
  '--preload-file',
  help=(
    '''Path to file where preload info is recorded. It is used to check if a given AppPkg is
    preloaded or not. Preload info for AppPkgs is also recorded in this file if we are preloading
    an AppPkg. Required for AppPkgs. See configure.sh: "is-preloaded" and "record-preload-info"
    functions.'''
  ),
  default='',
  nargs='?',
  type=str,
)

class InvalidInstallableError(Exception):
  """Error marking invalid installables."""

class GetCredentialError(Exception):
  """Error marking when we fail to get credentials."""

class DownloadError(Exception):
  """Error marking when a download fails."""

class CtrError(Exception):
  """Error when calls to 'ctr' fail."""

class PreloadError(Exception):
  """Error to mark preload errors."""

class GetCredentialError(Exception):
  """Error to mark failure to get credentials"""

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
      raise GetCredentialError(f'Failed to get credentials: status: {response.status} reason: {response.reason}')
    data = response.data.decode('utf-8')
    return json.loads(data)['access_token']

class Ctr:
  """Ctr is a wrapper around the container binary. It is used for faking in tests."""
  def download(self, url: str) -> subprocess.CompletedProcess:
    cmd = shlex.split(f'ctr -n k8s.io image pull --user="oauth2accesstoken:{get_gce_credentials()}" {url}')
    return subprocess.run(
      args=cmd,
      capture_output=True,
    )

  def list_images(self) -> subprocess.CompletedProcess:
    cmd = shlex.split('ctr -n k8s.io images list')
    return subprocess.run(
      args=cmd,
      capture_output=True,
    )

  def run(self, container_name: str, url: str, ctr_args: list, container_args: list) -> subprocess.CompletedProcess:
    ctr_flags = shlex.join(ctr_args)
    cont_args = shlex.join(container_args)
    cmd = shlex.split(f'ctr -n k8s.io run --rm {ctr_flags} {url} {container_name} {cont_args}')
    return subprocess.run(
      args=cmd,
      capture_output=True,
    )

  def delete(self, url: str):
    cmd = shlex.split(f'ctr -n k8s.io images delete {url}')
    subprocess.run(
      args=cmd,
      check=True,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
    )

ctr = Ctr()


class Installable:
  """Installable is the parent class for all installables."""

  def __init__(self, installable: Any, args: argparse.Namespace):
    if installable['metadata']['name'] == '':
      raise InvalidInstallableError('Name must not be omitted.')
    for f in ['remoteURL', 'digestAlgo', 'digest']:
      if f not in installable or installable[f] == "":
        raise InvalidInstallableError(f'Requred field "{f}" is omitted or emtpy')
    self.content = installable

  def __enter__(self):
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    return

  def download(self):
    raise NotImplementedError()

  def run(self):
    raise NotImplementedError()

  def is_preloaded(self):
    raise NotImplementedError()

  def name(self) -> str:
    return self.content['metadata']['name']

  def digest(self) -> str:
    return self.content['digest']

  def digest_algo(self) -> str:
    return self.content['digestAlgo']

  def get_url(self):
    raise NotImplementedError()

class Container(Installable):
  """A container kind installable.

  Container is an installable backed by a container. In this class, we use cri-tools to do
  operations like download and running the container.
  """

  def download(self):
    """Downloads the underlying container with ctr."""
    out = ctr.download(self.get_url())
    if out.returncode != 0:
      msg = out.stderr.strip()
      raise DownloadError(f'Failed to download container: return_code: {out.returncode} msg: {msg}')
    LOGGER.debug(f'Download result:')
    for l in out.stdout.splitlines():
      LOGGER.debug(l)

  def is_preloaded(self)->bool:
    """Use ctr to search the machine to make sure this container is preloaded."""
    out = ctr.list_images()
    if out.returncode != 0:
      err = out.stderr.strip()
      raise CtrError(f'Failed to run ctr: exit_code: {out.returncode} error: {err}')

    url = self.get_url()
    num_images = len(out.stdout.splitlines()) - 1
    LOGGER.debug(f'Total found images: {num_images}')
    return url in str(out.stdout.strip())

  def get_url(self) -> str:
    """Return the URL string for this container"""

    # For containers, this is of the form: gcr.io/path/to/container@sha256:checksum_string.
    return '%s@%s:%s' % (
        self.content['remoteURL'],
        self.digest_algo(),
        self.digest(),
    )

  def run(self):
    ctr_args = self.content.get('ctrArgs', [])
    container_args = self.content.get('containerArgs', [])
    out = ctr.run(self.name(), self.get_url(), ctr_args=ctr_args,  container_args=container_args)
    if out.returncode != 0:
      msg = out.stderr.strip()
      raise CtrError(f'Failed to run container: return_code: {out.returncode} msg: {msg}')
    LOGGER.debug(out.stdout)
    LOGGER.info(f'Running container {self.get_url()} succeeded.')

class AppPkgHandler:
  '''AppPkgHandler wraps methods that need to be faked for AppPkg unit tests.'''

  def download(self, retry: int, url: str)->bytes:
    creds = get_gce_credentials()
    retries = urllib3.util.Retry(
      total=retry,
      backoff_factor=1.0,
    )
    timeout = urllib3.util.Timeout(connect=20.0, read=10.0)
    with urllib3.PoolManager(
      retries=retries,
      timeout=timeout,
    ) as http:
      resp = http.request('GET', url,
                              headers={'Authorization': f'Bearer {creds}'})
      if resp.status != 200:
        raise IOError(f'Failed to download AppPkg: status: {resp.status} reason: {resp.reason}')
      return resp.data

  def checksum(self, file_path: str, algo: str, digest: str):
    """get_checksum computes the checksum for validating downloaded AppPkgs."""
    func = getattr(hashlib, algo.lower())
    LOGGER.debug(f'Using hash algo: {func.__name__}')
    if func is None:
      raise InvalidInstallableError('Unknown digest algo: %s' % algo)
    # we can choose different algos here as hashlib supports several.
    got_digest = ''
    with open(file_path, mode='rb') as f:
      got_digest = func(f.read()).hexdigest()
      LOGGER.debug(f'checking digest: got: {got_digest} want: {digest}')
      if got_digest != digest:
        raise DownloadError(f'mismatch digest: got: {got_digest} want: {digest}')

handler = AppPkgHandler()

class AppPkg(Installable):
  """Class to handle the apppkg kind.

  AppPkgs are files that are downloaded from some storage location, usually a GCS bucket.
  AppPkgs have been the primary type of legacy component on GKE: e.g. cni plugin, crictl, etc.
  """

  # Default retry to use for downloading AppPkgs from GCS buckets.
  retry = 6

  def __init__(self, installable: Any, args: argparse.Namespace):
    super().__init__(installable, args)
    # The preload file marks if an apppkg has been preloaded yet. This is usually
    # /home/kubernetes/preload_info with entries of the form {name}:{checksum}.
    if not os.path.exists(args.preload_file):
      raise argparse.ArgumentTypeError(f'Invalid preload file: "{args.preload_file}".')
    self.preload_file = args.preload_file
    if not args.output:
      raise argparse.ArgumentTypeError(f'Output file path is required for AppPkg installables.')
    self.output_file = args.output

  def __enter__(self):
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    return

  def download(self):
    """download function for apppkgs.

    Downloads an apppkg via urllib, validates the checksum, and records the apppkg as preloaded.
    """
    data = handler.download(retry=self.retry, url=self.get_url())
    with open(self.output_file, '+wb') as f:
      f.write(data)
    try:
      handler.checksum(file_path=self.output_file, algo=self.digest_algo(), digest=self.digest())
    except ValueError as e:
      raise DownloadError(f'Error validating package {self.name()}: {e=}')
    self._record_preload_info()

  def is_preloaded(self)->bool:
    """For apppkgs, check preload checks the preload file for an entry for this apppkg. Similar to
      the 'is-preloaded' method in configure.sh"""
    with open(self.preload_file, 'r') as f:
      content = f.read()
      name = re.escape(self.name())
      digest = re.escape(self.digest())
    regex = re.compile(fr'{name},{digest}')
    return True if regex.search(content) else False

  def run(self):
    LOGGER.info(f'AppPkg types do not have a run method. Returning.')

  def _record_preload_info(self):
    """records the preload info similar to the 'record-preload-info' function in configure.sh"""
    with open(self.preload_file, '+a') as f:
      f.write(f'{self.name()},{self.digest()}\n')

  def get_url(self) -> str:
    """AppPkg URLs are simply the given remoteURL."""
    return self.content['remoteURL'] if 'remoteURL' in self.content else ''

def parse_installable(args: argparse.Namespace) -> Installable:
  """parse_installable parses the given json installable returns the correct class based on kind"""
  if not args.installable:
    raise InvalidInstallableError(f'Cannot pass an empty installable!')
  inst = json.loads(args.installable)
  if inst['apiVersion'] != 'installable.gke.io/v1':
    raise InvalidInstallableError('Unknown api version: %s' % inst['apiVersion'])
  kind = inst['kind'].lower()
  if kind == 'container':
    return Container(inst, args)
  if kind == 'apppkg':
    return AppPkg(inst, args)
  raise InvalidInstallableError(f'Unknown installable type: {kind}')

def process_installable(args: argparse.Namespace):
  """process_installable validates and downloads the given installable"""
  with parse_installable(args) as inst:
    LOGGER.info(f'Processing installable: "{inst.name()}": url: "{inst.get_url()}"')
    if not args.no_download and not inst.is_preloaded():
      LOGGER.info(f'Installable not preloaded...downloading')
      inst.download()
    if not inst.is_preloaded():
      raise PreloadError(f'Installable {inst.name()} not preloaded.')
    if args.run:
      inst.run()

if __name__ == '__main__':
  args = parser.parse_args(sys.argv[1:])
  logging.basicConfig(level=args.loglevel)
  process_installable(args)