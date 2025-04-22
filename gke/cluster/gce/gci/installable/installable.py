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
import json
import logging
import os
import shlex
import subprocess
import sys
import urllib3


def setup_custom_logger(name: str):
    formatter = logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s',
                                  datefmt='%Y-%m-%d %H:%M:%S')
    screen_handler = logging.StreamHandler(stream=sys.stdout)
    screen_handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.addHandler(screen_handler)
    return logger

LOGGER= setup_custom_logger('installable')

parser = argparse.ArgumentParser()
parser.add_argument(
    '--installables',
    help='Installables described as a JSON blob.',
    required=True,
    type=str,
)

parser.add_argument(
    '--component',
    help='If set, process only the installables in a given component. Error if it doesn\'t exist',
    type=str,
    default='',
)

parser.add_argument(
    '-d', '--debug',
    help="Print debug statements",
    action="store_const", const=logging.DEBUG,
    default=logging.INFO,
)

parser.add_argument(
  '--download-restricted',
  help=(
    '''If true, we should not download files. This is to control booting from production'''
  ),
  action='store_true',
  default=False,
)

parser.add_argument(
  '--preloader',
  help=(
    '''Flags if the preloader is running this or not to inform container types.'''
  ),
  action='store_true',
  default=False,
)

parser.add_argument(
  '--record-file',
  help=(
    '''Path to file to place processed installables. This is for debugging and logging purposes.'''
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
  """Error to mark failure to get credentials."""

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
    LOGGER.debug(f'RUN COMMAND: {cmd}')
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

  def __init__(self, installable: dict):
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

  def run(self, is_preloader=False):
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
    """Return the URL string for this container."""

    # For containers, this is of the form: gcr.io/path/to/container@sha256:checksum_string.
    return '%s@%s:%s' % (
        self.content['remoteURL'],
        self.digest_algo(),
        self.digest(),
    )

  def run(self, is_preloader=False):
    run_spec = self.content.get('run', {})
    ctr_args = run_spec.get('ctrArgs', [])
    ctr_args.extend(['--env', f'GKE_PRELOADER_RUN={str(is_preloader).lower()}'])
    container_args = run_spec.get('containerArgs', [])
    out = ctr.run(self.name(), self.get_url(), ctr_args=ctr_args,  container_args=container_args)
    if out.returncode != 0:
      msg = out.stderr.strip()
      raise CtrError(f'Failed to run container: return_code: {out.returncode} msg: {msg}')
    LOGGER.debug(out.stdout)
    LOGGER.info(f'Running container {self.get_url()} succeeded.')

def parse_installable(inst: dict) -> Installable:
  """parse_installable parses the given json installable returns the correct class based on kind."""
  if inst['apiVersion'] != 'installable.gke.io/v1':
    raise InvalidInstallableError('Unknown api version: %s' % inst['apiVersion'])
  kind = inst['kind'].lower()
  if kind == 'container':
    return Container(inst)
  # AppPkgs will be removed as they'll require some more work.
  if kind == 'apppkg':
    raise InvalidInstallableError('Kind AppPkg is not supported for now')
  raise InvalidInstallableError(f'Unknown installable type: {kind}')

def process_installable(installable: Installable=None, download: bool=False, is_preloader=False):
  """process_installable validates and downloads the given installable."""
  if download and not installable.is_preloaded():
    LOGGER.info(f'Installable not preloaded...downloading')
    installable.download()
  if not installable.is_preloaded():
    raise PreloadError(f'Installable {installable.name()} not preloaded.')
  installable.run(is_preloader)

def process_installables(args: argparse.Namespace):
  """process_installables processes the given installables."""
  rendered_installables = json.loads(args.installables)
  download = not args.download_restricted
  LOGGER.info(f'Download setting: {download}')
  is_preloader = args.preloader
  LOGGER.info(f'Preloader setting: {is_preloader}')
  if args.component != '':
    LOGGER.info(f'Processsing only {args.component} installables')
    rendered_installables = {args.component: rendered_installables[args.component]}

  with Records(args.record_file) as records:
    comps = list(rendered_installables.keys())
    comps.sort()
    for component in comps:
      LOGGER.info(f'Processing component: "{component}"')
      objs = rendered_installables[component]
      objs_names = list(objs.keys())
      objs_names.sort()
      for object_name in objs_names:
        if records.contains(component, object_name):
          LOGGER.info(f'Object: "{component}:{object_name}" already processed.')
          continue
        LOGGER.info(f'Processing object "{object_name}"')
        with parse_installable(objs[object_name]) as inst:
          process_installable(inst, download=download, is_preloader=is_preloader)
          records.add(component=component, object=inst)
  LOGGER.info(f'Done processing installables.')

class Records():
  """Records manages the records of processed installables."""
  def __init__(self, path: str=''):
    self.path = path
    self.records = {}
    if path == '':
      return
    if not os.path.exists(self.path):
      open(self.path, 'w').close()

  def __enter__(self):
    if self.path != '':
      with open(self.path, 'r') as f:
        content = f.read()
        if content != '':
          self.records = json.loads(content)
    return self

  def __exit__(self, type, value, traceback):
    if self.path != '':
      with open(self.path, 'w') as f:
        f.seek(0)
        f.write(json.dumps(self.records))

  def contains(self, component: str='', object_name: str='') -> bool:
    """contains returns true if an entry matches object and component name, false otherwise."""
    if component == '':
      return False

    if component not in self.records.keys():
      return False

    if object == '':
      return False

    objs = self.records[component]

    if object_name not in objs.keys():
      return False

    return True

  def add(self, component: str='', object: Installable=None):
    """add adds an entry in the registry."""
    if component not in self.records.keys():
      self.records[component] = {}
    objs = self.records[component]
    if object.name() in objs:
      raise KeyError(msg=f'Duplicate record attempted: {object.name()}')
    objs[object.name()] = object.content


if __name__ == '__main__':
  args = parser.parse_args(sys.argv[1:])
  LOGGER.setLevel(args.debug)
  process_installables(args)