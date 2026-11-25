<!-- ----------------------------------------------------------------------------
  Copyright (c) 2026 Contributors to the Eclipse Foundation

  See the NOTICE file(s) distributed with this work for additional
  information regarding copyright ownership.

  This program and the accompanying materials are made available under the
  terms of the Apache License Version 2.0 which is available at
  https://www.apache.org/licenses/LICENSE-2.0

  SPDX-License-Identifier: Apache-2.0
----------------------------------------------------------------------------- -->

# Crypto daemon configuration: FlatBuffers and JSON workflow

##

1. The FlatBuffers schema file  present in ``score/crypto/src/daemon/config/crypto_config.fbs`` is the single source of truth.
2. Decision on seletioon of schema between fbs and json file is pending at score level. In order to Convert the `.fbs` to a JSON Schema. Use `bazel build //score/crypto/src/daemon/config:crypto_fbs_to_json_schema`.
4. Use `crypto_config_binary` from `//score/crypto/src/daemon/config:crypto_config.bzl` for daemon configuration binaries. It validates the JSON against the freshly generated JSON Schema as a required build action; invalid configurations stop the build.
5. After validation, the macro passes the unchanged JSON and the FlatBuffers schema to `flatc` to generate the binary, for example through `bazel build //score/crypto/tests/key_management/config:generate_key_management_test_config`. JSON Schema does not replace the FlatBuffers schema for serialization.

### Open points

1. Name of the generated flatbuffer bin file is set in the bazel rule. No specific naming convention is defined yet.


Concept for configuration for score::crypto
============================================

Goals
======
1. Concept shall align with stakeholder requirements, central concept and decision records of eclipse score.
2. Shall be extensible for the vendor distributions.
3. Loose coupling with user applications.
4. Ease of use : there shall be possibility of fallback default values, which the integrator/ user can reuse across applications instead of forcing to configure for every application.
5. Cross Module accessibility. Middleware processes may access Keys using the same ``AppKeySlotMapping`` which applications also use, why do we need a seperate element ?. For Private Key mapped to certificate, added ``private_key_slot_name`` under ``CertSlotEntry``.
6. Absolute and relative paths for key and certs : Added, however this leaves scope for misconfiguration which has to be caught during parsing.
7. Enforcing common interface for additional schema fbs files used  schema file added for PKCS11 backend : What is the rationale behind it ?
   Note : Currently keyslot holds algorithm.

Stakeholder requirements
========================
1. Decision record : https://eclipse-score.github.io/score/main/features/configuration/config_model/index.html#doc__configuration_model


Important Notes
================

The JSON Schema validation rule in `bazel/tools/json_schema_validator.bzl` was copied from the communication repository and extended locally. The schema-export script `generate_schema.py` and the validate-before-serialize macro `crypto_config.bzl` are crypto-specific additions, not verbatim copies. A better approach is to expose the common generation and validation tooling through shared Bazel dependencies, such as `score_baselibs` or `score_tooling`, and reuse it in both repositories instead of maintaining copied implementations.

Open points
=============
1. Configuration Philosophy : How do we reduce boilerplate for the user while keeping the configured values transparent? Should missing values always fall back to defaults (optionally emitting a warning), or should the user always be required to set them explicitly?
2. Profile based config : What is configurable, is it only the profile name in json config ? Does the default values of elements present in source code or json or specified in the schema ? 
3. Cross Module handling : Collect input from other Modules and within SEC IG.
