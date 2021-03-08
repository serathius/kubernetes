#!/usr/bin/env python3

# Copyright 2021 The Kubernetes Authors.
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

def main(gpu_partition_size, max_time_shared_clients_per_gpu, max_shared_clients_per_gpu, gpu_sharing_strategy, file_path):
  accelerator_config = {}
  if (len(gpu_partition_size)):
      accelerator_config["GPUPartitionSize"] = gpu_partition_size

  if (len(max_time_shared_clients_per_gpu)):
      accelerator_config["MaxTimeSharedClientsPerGPU"] = int(max_time_shared_clients_per_gpu)

  # max_shared_clients_per_gpu and gpu_sharing_strategy should exist together.
  if (len(max_shared_clients_per_gpu)):
      gpu_sharing_config = {}
      gpu_sharing_config["MaxSharedClientsPerGPU"] = int(max_shared_clients_per_gpu)
      if (len(gpu_sharing_strategy)):
          gpu_sharing_config["GPUSharingStrategy"] = gpu_sharing_strategy
      accelerator_config["GPUSharingConfig"] = gpu_sharing_config

  dump_to_file(accelerator_config, file_path)

if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(
        description='Generates the GPU configuration file for GKE nodes.')
    PARSER.add_argument(
        '--gpu-partition-size',
        type=str,
        required=True,
        help='Partition size for GPU in MIG strategy.')
    PARSER.add_argument(
        '--max-time-shared-clients-per-gpu',
        type=str,
        required=True,
        help='Max shared clients per GPU for time-sharing strategy.')
    PARSER.add_argument(
        '--max-shared-clients-per-gpu',
        type=str,
        required=True,
        help='Max shared clients per GPU for GPU sharing strategy.')
    PARSER.add_argument(
        '--gpu-sharing-strategy',
        type=str,
        required=True,
        help='GPU sharing strategy.')
    PARSER.add_argument(
        '--file-path',
        type=str,
        required=True,
        help='Path to write out GPU config.')
    ARGS = PARSER.parse_args()

    main(ARGS.gpu_partition_size, ARGS.max_time_shared_clients_per_gpu, ARGS.max_shared_clients_per_gpu, ARGS.gpu_sharing_strategy, ARGS.file_path)
