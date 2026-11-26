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
"""Validate crypto configuration JSON before serializing it as a FlatBuffer."""

load("@score_baselibs//score/flatbuffers/bazel:tools.bzl", "serialize_buffer")
load("//bazel/tools:json_schema_validator.bzl", "validate_json")

visibility(["//..."])

def crypto_config_binary(name, data, output, visibility = None):
    """Generate a binary from JSON validated against the current .fbs-derived schema.

    Args:
        name: Binary generation target name.
        data: Authored JSON configuration.
        output: FlatBuffer binary output name.
        visibility: Visibility of the binary generation target.
    """
    validated_name = name + "_validated_json"
    validate_json(
        name = validated_name,
        json = data,
        schema = "//score/crypto/src/daemon/config:crypto_fbs_to_json_schema",
        visibility = ["//visibility:private"],
    )
    serialize_buffer(
        name = name,
        data = ":" + validated_name,
        schema = "//score/crypto/src/daemon/config:crypto_config_fbs_schema",
        output = output,
        visibility = visibility,
    )