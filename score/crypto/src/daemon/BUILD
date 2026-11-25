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

load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")

TSAN_COPTS = select({
    "//conditions:default": [],
    ":tsan_enabled": [
        "-fsanitize=thread",
        "-g",
        "-O1",
    ],
})

TSAN_LINKOPTS = select({
    "//conditions:default": [],
    ":tsan_enabled": [
        "-fsanitize=thread",
    ],
})

cc_library(
    name = "crypto_daemon_lib",
    srcs = [
        "src/crypto_daemon.cpp",
        "src/daemon_component_factory.cpp",
        "src/disconnect_cleanup_callback.cpp",
    ],
    hdrs = [
        "src/crypto_daemon.hpp",
        "src/daemon_component_factory.hpp",
        "src/disconnect_cleanup_callback.hpp",
    ],
    copts = TSAN_COPTS,
    includes = ["IPC"],
    linkopts = TSAN_LINKOPTS,
    linkstatic = True,
    deps = [
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/config",
        "//score/crypto/src/daemon/control_plane",
        "//score/crypto/src/daemon/data_manager",
        "//score/crypto/src/daemon/data_plane",
        "//score/crypto/src/daemon/key_management",
        "//score/crypto/src/daemon/mediator",
        "//score/crypto/src/daemon/provider:provider_manager",
        "//score/crypto/src/daemon/provider:provider_manager_factory",
        "//score/crypto/src/ipc/message_passing_adapter:ipc_config",
        "//score/crypto/src/ipc/message_passing_adapter:message_passing_server",
        "@score_baselibs//score/concurrency:interruptible_wait",
        "@score_baselibs//score/mw/log",
        "@score_communication//score/memory/shared",
        "@score_lifecycle//score/launch_manager:lifecycle_cc",
    ],
)

cc_binary(
    name = "crypto_daemon",
    srcs = ["src/daemon.cpp"],
    copts = TSAN_COPTS,
    dynamic_deps = select({
        "@score_openssl//:dynamic_openssl_enabled": [
            "@score_openssl//:openssl_shared",
            "//score/crypto/src/backend:pkcs11_shared_backend",
        ],
        "//conditions:default": [],
    }),
    linkopts = TSAN_LINKOPTS,
    linkstatic = True,
    visibility = ["//visibility:public"],
    deps = [
        ":crypto_daemon_lib",
        "@score_lifecycle//score/launch_manager:lifecycle_cc",
    ],
)

cc_test(
    name = "crypto_daemon_unit_test",
    srcs = ["src/crypto_daemon_test.cpp"],
    deps = [
        ":crypto_daemon_lib",
        "@googletest//:gtest_main",
        "@score_lifecycle//score/launch_manager:lifecycle_cc",
    ],
)

cc_test(
    name = "daemon_component_factory_unit_test",
    srcs = ["src/daemon_component_factory_test.cpp"],
    deps = [
        ":crypto_daemon_lib",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "disconnect_cleanup_callback_unit_test",
    srcs = ["src/disconnect_cleanup_callback_test.cpp"],
    deps = [
        ":crypto_daemon_lib",
        "//score/crypto/src/daemon/data_manager",
        "@googletest//:gtest_main",
    ],
)

# Configuration for enabling ThreadSanitizer
config_setting(
    name = "tsan_enabled",
    values = {
        "define": "tsan=1",
    },
)
