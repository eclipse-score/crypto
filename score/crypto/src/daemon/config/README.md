<!-- ----------------------------------------------------------------------------
  Copyright (c) 2026 Contributors to the Eclipse Foundation

  See the NOTICE file(s) distributed with this work for additional
  information regarding copyright ownership.

  This program and the accompanying materials are made available under the
  terms of the Apache License Version 2.0 which is available at
  https://www.apache.org/licenses/LICENSE-2.0

  SPDX-License-Identifier: Apache-2.0
----------------------------------------------------------------------------- -->

# Crypto daemon configuration

## Overview and status

This document describes the current configuration workflow for `score::crypto`,
the configuration and parser design goals, and the questions that remain open.

The FlatBuffers schema [crypto_config.fbs](crypto_config.fbs) is currently the
single source of truth. The SCORE-wide decision on whether FlatBuffers or JSON
Schema should be the authoritative schema format is still pending.

## Configuration workflow

The current workflow is:

1. Generate a JSON Schema from the FlatBuffers schema.
2. Validate the configuration JSON against the generated JSON Schema.
3. Serialize the validated JSON into a FlatBuffer binary using the FlatBuffers schema.

### Generate the JSON Schema

Use the Bazel target `//score/crypto/src/daemon/config:crypto_fbs_to_json_schema`
to build the generated JSON Schema.

Use `//score/crypto/src/daemon/config:generate_schema` with `bazel run` to
regenerate and copy the schema into
[crypto_config.schema.json](crypto_config.schema.json) alongside the ``.fbs`` schema.

### Validate and serialize configuration JSON

Use the `crypto_config_binary` macro from
[crypto_config.bzl](crypto_config.bzl) to create daemon configuration binaries.
The macro validates the JSON against the freshly generated JSON Schema as a
required build action. Invalid configurations stop the build.

After validation, the macro passes the unchanged JSON and the FlatBuffers schema
to `flatc` for binary generation. JSON Schema is used for validation; it does not
replace the FlatBuffers schema for serialization.

For example, build the key-management test configuration with `bazel build` and
the target `//score/crypto/tests/key_management/config:generate_key_management_test_config`.

## Configuration design goals

- **Alignment:** Align the configuration concept with Eclipse SCORE stakeholder
  requirements, the central configuration concept, and applicable decision records.
- **Extensibility:** Support extensions for vendor distributions.
- **Loose coupling:** Keep the configuration loosely coupled to user applications.
- **Ease of use:** Allow integrators and users to reuse default values across
  applications rather than requiring repetitive configuration for each application.
  The policy for applying defaults remains an open question.
- **Cross-module access:** Support configuration needs shared by applications and
  middleware processes. Whether these clients should use the same mappings or
  separate elements remains an open question.

### Existing schema considerations

- Middleware processes may access keys through the same `AppKeySlotMapping` used
  by applications. The need for a separate middleware-specific element requires clarification.
- `CertSlotEntry` includes `private_key_slot_name` to map a certificate to its private key.
- Absolute and relative paths are supported for keys and certificates. Path
  misconfigurations must be detected during parsing.
- An additional FlatBuffers schema has been introduced for the PKCS11 backend.
  The rationale for a common interface across backend-specific schemas remains open.
  Key slots currently contain algorithm information.

## Tooling and reuse

The JSON Schema validation rule in
[json_schema_validator.bzl](../../../../../bazel/tools/json_schema_validator.bzl)
was copied from the communication repository and extended locally.

The schema-export script [generate_schema.py](generate_schema.py) and the
validate-before-serialize macro [crypto_config.bzl](crypto_config.bzl) are
crypto-specific additions, not verbatim copies.

A proposed improvement is to expose common schema-generation and validation
tooling through shared Bazel dependencies, such as `score_baselibs` or
`score_tooling`. Both repositories could then reuse this tooling rather than
maintaining copied implementations.

## Open design questions

### Default values and configuration transparency

How can configuration boilerplate be reduced while keeping the effective values
transparent to users? Should missing values always fall back to defaults,
optionally emitting a warning, or should users be required to set them explicitly?

### Profile-based configuration

What should be configurable through a profile? Should users specify only a profile
name in the JSON configuration, or should individual values also be configurable?
Where should default values be defined: in source code, configuration JSON, or the schema?

### Cross-module configuration

Can applications and middleware processes share `AppKeySlotMapping`, or is a
separate configuration element needed? Collect input from other SCORE modules
and the Security Interest Group (SEC IG).

### Backend-specific schemas

What is the rationale for enforcing a common interface across additional
FlatBuffers schemas, including the PKCS11 backend schema? How should this relate
to the algorithm information already held by key slots?

### Binary filename conventions

The generated FlatBuffer binary filename is set by the Bazel rule. No common
naming convention has been defined yet.

## References

- [SCORE configuration model decision record](https://eclipse-score.github.io/score/main/features/configuration/config_model/index.html#doc__configuration_model)