# *******************************************************************************
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
# *******************************************************************************
"""Export the Bazel-generated JSON Schema alongside crypto_config.fbs."""

import argparse
import os
from pathlib import Path
import shutil


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("schema", type=Path, help="Bazel-generated JSON Schema")
    args = parser.parse_args()

    workspace = os.environ.get("BUILD_WORKSPACE_DIRECTORY")
    if not workspace:
        parser.error("BUILD_WORKSPACE_DIRECTORY is not set; run via bazel run")

    destination = (
        Path(workspace)
        / "score/crypto/src/daemon/config/crypto_config.schema.json"
    )
    shutil.copyfile(args.schema, destination)
    print(f"Updated {destination}")


if __name__ == "__main__":
    main()