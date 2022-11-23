#!/usr/bin/env python3

# Copyright 2022 The Kubernetes Authors.
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

import argparse
import json

def dump_to_file(conf, filename):
  with open(filename, 'w') as output_file:
    output_file.write(json.dumps(conf, indent=2))
    output_file.write('\n')

def main(tpu_accelerator_type, tpu_topology, file_path):
  tpu_config = {}
  if (len(tpu_accelerator_type)):
      tpu_config["TPUAcceleratorType"] = tpu_accelerator_type

  if (len(tpu_topology)):
      tpu_config["TPUTopology"] = tpu_topology

  dump_to_file(tpu_config, file_path)

if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(
        description='Generates the TPU configuration file for GKE nodes.')
    PARSER.add_argument(
        '--tpu-accelerator-type',
        type=str,
        required=True,
        help='TPU accelerator type (i.e. "tpu-<gen>-<podslice/lite>")')
    PARSER.add_argument(
        '--tpu-topology',
        type=str,
        required=True,
        help='TPU topology (e.g. 2x2x2)')
    PARSER.add_argument(
        '--file-path',
        type=str,
        required=True,
        help='File path of the output JSON file')
    ARGS = PARSER.parse_args()

    main(ARGS.tpu_accelerator_type, ARGS.tpu_topology, ARGS.file_path)
