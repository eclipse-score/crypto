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
4. Validate the JSON config against the JSON Schema : defered for now, is already handled by point 5 below.
5. Generate a FlatBuffers binary from the `.fbs` and the JSON config : accomplished by using ``flatc`` command, bazel rule is invoking it in the repo. ex. ``bazel build //score/crypto/tests/key_management/config:generate_key_management_test_config``

### Open points

1. Name of the generated flatbuffer bin file is set in the bazel rule. No specific naming convention is defined yet.


Concept for configuration for score::crypto
============================================

Goals
======
1. Concept shall align with stakeholder requirements, central concept and decision records of eclipse score.
2. Shall be extensible for the vendor distributions.
3. Loose coupling with user applications.
4. Ease of use : there shall be possibility of fallback default values, which the integrator/ user can reuse across applications instead of focrcing to configure for every application.
5. Cross Module accessibility. Middleware processes may access Keys using the same ``AppKeySlotMapping`` which applications also use, why do we need a seperate element ?. For Private Key mapped to certificate, added ``private_key_slot_name`` under ``CertSlotEntry``.
6. Absolute and relative paths for key and certs : Added, however this leaves scope for misconfiguration which has to be caught during parsing.
7. Enforcing common interface for additonal schema fbs files used  schema file added for PKCS11 backend : What is the rationale behind it ?


Goals of Config Parser
=======================
1. Shall support reparsing and reloading of the config.
2. Individual logical group of config shall be broken into seperate classes, in order not to force clients not to depend on config which they do not need.

Stakeholder requirements
========================
1. Decisioon record : https://eclipse-score.github.io/score/main/features/configuration/config_model/index.html#doc__configuration_model
