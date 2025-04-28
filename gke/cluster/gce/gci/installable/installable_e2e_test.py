# Copyright 2025 The GKE Authors.
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

"""e2e test for installables.

This test exercises the e2e installable workflow.
"""

import argparse
import copy
import installable
import json
import logging
import os
import pathlib
import tempfile
import unittest


INSTALLABLE_SCRIPT_PATH = str(pathlib.Path(__file__).parent.absolute().joinpath("installable.py"))

OUTFILE = '/tmp/something'
FILE_CONTENT = 'something'
PRINTER_CONTENT = 'This is the printer!'

DEFAULT_INSTALLABLES = {
    "component1": {
        "mount": {
            "kind":"container",
            "apiVersion":"installable.gke.io/v1",
            "metadata":{
                "name":"mount",
            },
            "os":"linux",
            "arch":"MULTI",
            "version":"1.4.5",
            "remoteURL":"gcr.io/gke-release-staging/gke-distroless/bash:gke_distroless_20241207.00_p0",
            "digest":"9bd9f35657b03f55a00a33feac0500ee183dcfd5f7f1982cd35a7a032953d466",
            "digestAlgo":"sha256",
            "run": {
                "ctrArgs": ["--privileged", "--mount", "type=bind,src=/,dst=/host,options=rbind"],
                "containerArgs": ["bash", "-c", f"echo {FILE_CONTENT} > {'/host' + OUTFILE}"],
            }
        },
        "printer": {
            "kind":"container",
            "apiVersion":"installable.gke.io/v1",
            "metadata":{
                "name":"printer",
            },
            "os":"linux",
            "arch":"MULTI",
            "version":"1.2.3",
            "remoteURL":"gcr.io/gke-release-staging/gke-distroless/bash:gke_distroless_20250107.00_p0",
            "digest":"12d99a6a72f4fecd689ead5d93001c1f3acea08ec72a55bbdfc070e0edc30fa4",
            "digestAlgo":"sha256",
            "run": {
                "ctrArgs": [],
                "containerArgs": ["bash", "-c", f"echo '{PRINTER_CONTENT}'"],
            }
        },
    },
    "component2": {
        "env": {
            "kind":"container",
            "apiVersion":"installable.gke.io/v1",
            "metadata":{
                "name":"env",
            },
            "os":"linux",
            "arch":"MULTI",
            "version":"1.9.2",
            "remoteURL":"gcr.io/gke-release-staging/gke-distroless/bash:gke_distroless_20241207.00_p0",
            "digest":"9bd9f35657b03f55a00a33feac0500ee183dcfd5f7f1982cd35a7a032953d466",
            "digestAlgo":"sha256",
            "run": {
                "containerArgs": ["bash", "-c", "printenv"],
            }
        },
    },
}


class InstallablePyTests(unittest.TestCase):
    """InstallablePyTests test installably.py only."""

    def setUp(self):
        super().setUp()
        cleanup(DEFAULT_INSTALLABLES)

    def tearDown(self):
        super().tearDown()
        if os.path.exists(OUTFILE):
            os.remove(OUTFILE)

    def test_successful_run(self):
        """Tests the common case of running on preload and boot"""
        with tempfile.NamedTemporaryFile() as record:
            # First the preloader runs, which will download the images.
            with self.assertLogs(logger=installable.LOGGER, level=logging.DEBUG) as logs:
                args = make_args(installables=DEFAULT_INSTALLABLES, is_preload=True, download_restricted=False, record_path=record.name)
                installable.process_installables(args=args)
                output = ''.join(logs.output)
                self.assertIn(PRINTER_CONTENT, output, str(logs.output))
                self.assertIn("GKE_PRELOADER_RUN=true", output, str(logs.output))
                record.seek(0)
                results = json.loads(record.read())
                self.assertEqual(len(results.keys()), len(DEFAULT_INSTALLABLES.keys()))
                for component in results.keys():
                    self.assertIn(component, DEFAULT_INSTALLABLES.keys(), component)
                    self.assertEqual(len(results[component]), len(DEFAULT_INSTALLABLES[component]),
                                    results[component])
                with open(OUTFILE, 'r') as outfile:
                    self.assertIn(FILE_CONTENT, outfile.read())

        with tempfile.NamedTemporaryFile() as record:
            # On boot, we do not download images, they should already be preloaded.
            with self.assertLogs(logger=installable.LOGGER, level=logging.DEBUG) as logs:
                args = make_args(installables=DEFAULT_INSTALLABLES, is_preload=False, download_restricted=True, record_path=record.name)
                installable.process_installables(args=args)
                output = ''.join(logs.output)
                self.assertIn(PRINTER_CONTENT, output, str(logs.output))
                self.assertIn("GKE_PRELOADER_RUN=false", output, str(logs.output))
                with open(OUTFILE, 'r') as outfile:
                    self.assertIn(FILE_CONTENT, str(outfile.read()))
                os.remove(OUTFILE)

    def test_process_one_component(self):
        '''Tests that we only process one component if the --component argument is set.'''
        with tempfile.NamedTemporaryFile() as record:
            # First the preloader runs, which will download the images.
            with self.assertLogs(logger=installable.LOGGER, level=logging.DEBUG) as logs:
                args = make_args(installables=DEFAULT_INSTALLABLES, is_preload=True, download_restricted=False, record_path=record.name, component='component2')
                installable.process_installables(args=args)
                output = '\n'.join(logs.output)
                self.assertNotIn(PRINTER_CONTENT, output, str(output))
                record.seek(0)
                results = json.loads(record.read())
                self.assertEqual(len(results.keys()), 1)
                self.assertIn('component2', results.keys())
                self.assertFalse(os.path.exists(OUTFILE), str(output))

    def test_process_one_component_once(self):
        '''Tests that we process components only once on multiple runs.'''
        with tempfile.NamedTemporaryFile() as record:
            # First the preloader runs, which will download the images.
            with self.assertLogs(logger=installable.LOGGER, level=logging.DEBUG) as logs:
                args = make_args(installables=DEFAULT_INSTALLABLES, is_preload=True,
                                 download_restricted=False, record_path=record.name, component='component2')
                installable.process_installables(args=args)
                output = '\n'.join(logs.output)
                self.assertNotIn(PRINTER_CONTENT, output, str(output))
                record.seek(0)
                results = json.loads(record.read())
                self.assertEqual(len(results.keys()), 1)
                self.assertNotIn(PRINTER_CONTENT, output, str(output))
                self.assertIn('component2', results.keys())
                self.assertFalse(os.path.exists(OUTFILE), str(output))
            logs = None
            with self.assertLogs(logger=installable.LOGGER, level=logging.DEBUG) as logs:
                args = make_args(installables=DEFAULT_INSTALLABLES, is_preload=True,
                                 download_restricted=False, record_path=record.name)
                installable.process_installables(args=args)
                record.seek(0)
                results = json.loads(record.read())
                output = '\n'.join(logs.output)
                self.assertEqual(len(results.keys()), len(DEFAULT_INSTALLABLES.keys()))
                self.assertIn(PRINTER_CONTENT, output, str(output))
                with open(OUTFILE, 'r') as outfile:
                    self.assertIn(FILE_CONTENT, str(outfile.read()))

    def test_boot_without_preload_fails(self):
        """Test the case where we have downloads restricted and haven't preloaded"""
        with tempfile.NamedTemporaryFile() as record:
            with self.assertLogs(logger=installable.LOGGER, level=logging.INFO):
                with self.assertRaisesRegex(installable.PreloadError, 'Installable mount not preloaded.'):
                    args = make_args(installables=DEFAULT_INSTALLABLES, download_restricted=True, record_path=record.name)
                    installable.process_installables(args=args)
                    record.seek(0)
                    self.assertEqual(json.loads(record.read()), {})

    def test_broken_installable_fails(self):
        """Tests the case where there is a broken installable"""
        with tempfile.NamedTemporaryFile() as record:
            with self.assertLogs(logger=installable.LOGGER, level=logging.INFO):
                installables = copy.deepcopy(DEFAULT_INSTALLABLES)
                installables['component2']['env']['digest'] = 'garbage'
                with self.assertRaisesRegex(installable.DownloadError, 'invalid checksum digest length'):
                    args = make_args(installables=installables, download_restricted=False, record_path=record.name)
                    installable.process_installables(args)
                # We should get records of the installables that loaded succesfully in order.
                record.seek(0)
                installables.pop('component2')
                results = json.loads(record.read())
                self.assertEqual(len(results.keys()), len(installables.keys()))
                for component in results.keys():
                    self.assertIn(component, installables.keys(), component)
                    self.assertEqual(len(results[component]), len(installables[component]),
                                    results[component])

    def test_successful_run_with_preload_info(self):
        """Tests the common case where the image URL during preload is different
        from the image URL during boot due to Artifact Registry migration."""
        with tempfile.NamedTemporaryFile() as preload_record:
            # First the preloader runs, which will download the images.
            with self.assertLogs(logger=installable.LOGGER, level=logging.DEBUG) as logs:
                args = make_args(installables=DEFAULT_INSTALLABLES, is_preload=True, download_restricted=False, record_path=preload_record.name)
                installable.process_installables(args=args)
                output = ''.join(logs.output)
                self.assertIn(PRINTER_CONTENT, output, str(logs.output))
                self.assertIn("GKE_PRELOADER_RUN=true", output, str(logs.output))
                preload_record.seek(0)
                results = json.loads(preload_record.read())
                self.assertEqual(len(results.keys()), len(DEFAULT_INSTALLABLES.keys()))
                for component in results.keys():
                    self.assertIn(component, DEFAULT_INSTALLABLES.keys(), component)
                    self.assertEqual(len(results[component]), len(DEFAULT_INSTALLABLES[component]),
                                    results[component])
                with open(OUTFILE, 'r') as outfile:
                    self.assertIn(FILE_CONTENT, outfile.read())

            with tempfile.NamedTemporaryFile() as record:
                # On boot, we generally provide regionalized URLs, but we should still succeed.
                with self.assertLogs(logger=installable.LOGGER, level=logging.DEBUG) as logs:
                    installables = copy.deepcopy(DEFAULT_INSTALLABLES)
                    installables["component1"]["mount"]["remoteURL"] = "us-central1-artifactregistry.gcr.io/gke-release-staging/gke-release-staging/gke-distroless/bash:gke_distroless_20241207.00_p0"
                    installables["component1"]["printer"]["remoteURL"] = "us-central1-artifactregistry.gcr.io/gke-release-staging/gke-release-staging/gke-distroless/bash:gke_distroless_20250107.00_p0"
                    installables["component2"]["env"]["remoteURL"] = "us-central1-artifactregistry.gcr.io/gke-release-staging/gke-release-staging/gke-distroless/bash:gke_distroless_20241207.00_p0"
                    args = make_args(installables=installables, is_preload=False, download_restricted=True, record_path=record.name, preload_info_path=preload_record.name)
                    installable.process_installables(args=args)
                    output = ''.join(logs.output)
                    self.assertIn(PRINTER_CONTENT, output, str(logs.output))
                    self.assertIn("GKE_PRELOADER_RUN=false", output, str(logs.output))
                    self.assertIn("Retagging image in object", output, str(logs.output))
                    with open(OUTFILE, 'r') as outfile:
                        self.assertIn(FILE_CONTENT, str(outfile.read()))
                    os.remove(OUTFILE)

    def test_installable_without_preload_info_fails(self):
        """Tests the unusual case where the installable is not preloaded but
        enabled during runtime."""
        with tempfile.NamedTemporaryFile() as preload_record:
            with self.assertLogs(logger=installable.LOGGER, level=logging.DEBUG) as logs:
                # Preload all the installables except component1:printer.
                installables = copy.deepcopy(DEFAULT_INSTALLABLES)
                del installables["component1"]["printer"]
                args = make_args(installables=installables, is_preload=True, download_restricted=False, record_path=preload_record.name)
                installable.process_installables(args=args)
                output = ''.join(logs.output)
                self.assertIn("GKE_PRELOADER_RUN=true", output, str(logs.output))
                preload_record.seek(0)
                results = json.loads(preload_record.read())
                self.assertEqual(len(results.keys()), len(installables.keys()))
                for component in results.keys():
                    self.assertIn(component, installables.keys(), component)
                    self.assertEqual(len(results[component]), len(installables[component]),
                                    results[component])
                with open(OUTFILE, 'r') as outfile:
                    self.assertIn(FILE_CONTENT, outfile.read())

            with tempfile.NamedTemporaryFile() as record:
                # On boot, we generally provide regionalized URLs.
                # For unexpected reasons, component1:printer was enabled during
                # runtime, but not preloaded.
                with self.assertLogs(logger=installable.LOGGER, level=logging.DEBUG) as logs:
                    installables = copy.deepcopy(DEFAULT_INSTALLABLES)
                    installables["component1"]["mount"]["remoteURL"] = "us-central1-artifactregistry.gcr.io/gke-release-staging/gke-release-staging/gke-distroless/bash:gke_distroless_20241207.00_p0"
                    installables["component1"]["printer"]["remoteURL"] = "us-central1-artifactregistry.gcr.io/gke-release-staging/gke-release-staging/gke-distroless/bash:gke_distroless_20250107.00_p0"
                    installables["component2"]["env"]["remoteURL"] = "us-central1-artifactregistry.gcr.io/gke-release-staging/gke-release-staging/gke-distroless/bash:gke_distroless_20241207.00_p0"
                    # We should fail to process component2 because it was not preloaded.
                    with self.assertRaisesRegex(installable.PreloadError, 'Installable printer not preloaded.'):
                        args = make_args(installables=installables, is_preload=False, download_restricted=True, record_path=record.name, preload_info_path=preload_record.name)
                        installable.process_installables(args=args)

def make_args(installables: dict=None, is_preload: bool=False, download_restricted: bool=False, record_path: str='', component: str='', preload_info_path: str='') -> argparse.Namespace:
    args = ['--installables', json.dumps(installables),
        '--component', component,
        '--record-file', record_path]
    if is_preload:
        args.append('--preloader')
    if download_restricted:
        args.append('--download-restricted')
    if preload_info_path:
        args.extend(['--preload-info-file', preload_info_path])
    return installable.parser.parse_args(args)


def cleanup(installables: dict=None):
    local_dict = {}
    if installables is not None:
        local_dict = copy.deepcopy(installables)
    ctr = installable.Ctr()
    for _, installables in local_dict.items():
        for inst_name in installables.keys():
            obj = installables[inst_name]
            image = f'{obj["remoteURL"]}@sha256:{obj["digest"]}'
            images = str(ctr.list_images().stdout)
            if image in images:
                installable.Ctr().delete(url=image)

if __name__ == '__main__':
    installable.ctr = installable.Ctr(container_run_output=False)
    unittest.main()