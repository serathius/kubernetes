#!/usr/bin/env python3

# Copyright 2026 Google
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

import os
import sys
import re
import glob

# The GKE hack verify boilerplate script runs from repo root or gke directory.
# Find repo root.
rootdir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
boilerplate_dir = os.path.join(rootdir, "hack/boilerplate")

def get_refs():
    refs = {}
    for path in glob.glob(os.path.join(boilerplate_dir, "boilerplate.*.txt")):
        extension = os.path.basename(path).split(".")[1]
        with open(path, "r") as ref_file:
            refs[extension] = ref_file.read().splitlines()
    return refs

def file_extension(filename):
    return os.path.splitext(filename)[1].split(".")[-1].lower()

# Regexes for parsing shebangs, build constraints, and normalizing copyrights.
regexs = {
    "go_build_constraints": re.compile(r"^(//(go:build| \+build).*\n)+\n", re.MULTILINE),
    "shebang": re.compile(r"^(#!.*\n)\n*", re.MULTILINE),
    "generated": re.compile(r"^[/*#]+ +.* DO NOT EDIT\.$", re.MULTILINE),
    # we allow Kubernetes because some files are forked and should retain Kubernetes copyright
    # totally new downstream-only files should have Google
    "gke_copyright": re.compile(
        r"Copyright\s+([0-9,\-\s]+)?(The Kubernetes Authors|Google)(?:\s+LLC)?\.?",
        re.IGNORECASE
    )
}

refs = get_refs()

def check_file(filename):
    try:
        with open(filename) as stream:
            data = stream.read()
    except OSError as exc:
        print(f"Unable to open {filename}: {exc}", file=sys.stderr)
        return False

    generated = regexs["generated"].search(data)
    basename = os.path.basename(filename)
    extension = file_extension(filename)
    if generated:
        if extension == "go":
            extension = "generatego"

    if extension in refs:
        ref = refs[extension]
    elif basename in refs:
        ref = refs[basename]
    else:
        # Not a file type we lint for boilerplate (e.g. yaml, md, etc.)
        return True

    # Strip leading constraints/shebangs for specific file types
    if extension in ("go", "generatego"):
        data, found = regexs["go_build_constraints"].subn("", data, 1)
    elif extension in ["sh", "py"]:
        data, found = regexs["shebang"].subn("", data, 1)

    data = data.splitlines()

    # If the file is smaller than the reference, it fails.
    if len(ref) > len(data):
        print(f"File {filename} smaller than reference ({len(data)} < {len(ref)})", file=sys.stderr)
        return False

    # Trim file to match reference boilerplate lines
    data = data[: len(ref)]

    if not generated:
        # Normalize any of the allowed GKE/Kubernetes copyright headers to standard reference header
        for i, line in enumerate(data):
            normalized, count = regexs["gke_copyright"].subn("Copyright The Kubernetes Authors.", line)
            if count != 0:
                data[i] = normalized
                break

    if ref != data:
        return False

    return True

def main():
    failed_files = []
    # The files walked by this script should match the set of files
    # We exclude from the upstream script via the companion shell script
    # (verify-boilerplate.sh)
    for root, dirs, files in os.walk(os.path.join(rootdir, "gke")):
        # Skip certain directories
        skip_dirs = ["__pycache__", os.path.join('build', 'tools', 'bin')]
        for skip_dir in skip_dirs:
            if skip_dir in dirs:
                dirs.remove(skip_dir)
        for file in files:
            path = os.path.join(root, file)
            if not check_file(path):
                failed_files.append(path)
    if failed_files:
        for path in failed_files:
            print(f"Boilerplate header is wrong for: {os.path.relpath(path, rootdir)}", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
