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
"""Validate JSON from standard input against a Draft 2020-12 schema."""

import argparse
import json
import sys

import jsonschema_rs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("schema")
    args = parser.parse_args()
    try:
        with open(args.schema, encoding="utf-8") as source:
            schema = json.load(source)
        validator = jsonschema_rs.Draft202012Validator(schema)
        validator.validate(json.load(sys.stdin))
    except (OSError, ValueError, jsonschema_rs.ValidationError) as error:
        print(f"JSON Schema validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())