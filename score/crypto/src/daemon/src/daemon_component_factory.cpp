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

#include "score/crypto/src/daemon/src/daemon_component_factory.hpp"

#include "score/crypto/src/daemon/provider/provider_manager_factory.hpp"
#include "score/crypto/src/ipc/message_passing_adapter/server/message_passing_control_server.h"

#include <utility>

namespace score::crypto::daemon
{

bool DaemonComponentFactory::ParseConfig(config::Config& config)
{
    return config.ParseConfig();
}

IDaemonComponentFactory::ProviderManagerResult DaemonComponentFactory::CreateProviderManager(config::Config& config)
{
    return provider::ProviderManagerFactory::Create(config);
}

IDaemonComponentFactory::ControlServerResult DaemonComponentFactory::CreateControlServer(
    std::unique_ptr<control_plane::IHandlerChainFactory> handler_factory,
    const config::IPCConfig& ipc_config,
    ipc::message_passing::AuthorizationCallback authorization,
    ipc::message_passing::DisconnectCleanupCallback cleanup_callback)
{
    using MessagePassingServer = ipc::message_passing::MessagePassingControlServer;

    auto server_result = MessagePassingServer::Create(
        std::move(handler_factory), ipc_config, std::move(authorization), std::move(cleanup_callback));
    if (!server_result.has_value())
    {
        return score::crypto::make_unexpected(server_result.error());
    }
    return std::unique_ptr<control_plane::IControlServer>{std::move(server_result).value()};
}

}  // namespace score::crypto::daemon
