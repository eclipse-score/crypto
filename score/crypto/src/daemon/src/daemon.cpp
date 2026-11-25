/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

#include "score/crypto/src/daemon/src/crypto_daemon.hpp"
#include "score/crypto/src/daemon/src/daemon_component_factory.hpp"

#include "score/mw/lifecycle/runapplication.h"

#include <memory>

int main(int argc, char** argv)
{
    return score::mw::lifecycle::run_application<score::crypto::daemon::CryptoDaemon>(
        argc, argv, std::make_unique<score::crypto::daemon::DaemonComponentFactory>());
}
