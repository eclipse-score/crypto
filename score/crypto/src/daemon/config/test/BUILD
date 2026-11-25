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

load("//bazel/tools:json_schema_validator.bzl", "validate_json_schema_test")

INVALID_JSON_FILES = [
    "test_key_config",
]

# Each file must be rejected by the JSON Schema generated from crypto_config.fbs.
# expected_failure = True makes a validation error the passing outcome.
[
    validate_json_schema_test(
        name = name + "_is_rejected",
        json = "test_json/" + name + ".json",
        schema = "//score/crypto/src/daemon/config:crypto_fbs_to_json_schema",
        expected_failure = True,
        tags = ["lint"],
        target_compatible_with = ["@platforms//os:linux"],
    )
    for name in INVALID_JSON_FILES
]

test_suite(
    name = "invalid_config_tests",
    tests = [name + "_is_rejected" for name in INVALID_JSON_FILES],
    tags = ["lint"],
)
