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

#ifndef SCORE_CRYPTO_SRC_DAEMON_SRC_DAEMON_COMPONENT_FACTORY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_SRC_DAEMON_COMPONENT_FACTORY_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/control_plane/i_control_server.h"
#include "score/crypto/src/daemon/control_plane/i_handler_chain_factory.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"
#include "score/crypto/src/ipc/message_passing_adapter/server/server_callbacks.hpp"

#include <memory>

namespace score::crypto::daemon
{

/**
 * @brief Creates the daemon components that a test replaces: the configuration, the provider manager and the control
 * server.
 *
 * CryptoDaemon builds everything else itself.
 */
class IDaemonComponentFactory
{
  public:
    using ProviderManagerResult =
        score::crypto::Expected<std::shared_ptr<provider::ProviderManager>, common::DaemonErrorCode>;
    using ControlServerResult =
        score::crypto::Expected<std::unique_ptr<control_plane::IControlServer>, common::DaemonErrorCode>;

    virtual ~IDaemonComponentFactory() = default;

    IDaemonComponentFactory(const IDaemonComponentFactory&) = delete;
    IDaemonComponentFactory& operator=(const IDaemonComponentFactory&) = delete;
    IDaemonComponentFactory(IDaemonComponentFactory&&) = delete;
    IDaemonComponentFactory& operator=(IDaemonComponentFactory&&) = delete;

    /**
     * @brief Fills @p config from the crypto stack configuration file.
     * @return False if CRYPTO_CONFIG_FILE names a missing file, or the resolved file cannot be inspected, read or
     *         parsed. True if a file was loaded or no file exists on the default paths.
     */
    virtual bool ParseConfig(config::Config& config) = 0;

    /**
     * @brief Creates the provider manager with every provider the configuration enables.
     * @note Parses the provider sections of @p config, so the call modifies it.
     */
    virtual ProviderManagerResult CreateProviderManager(config::Config& config) = 0;

    /**
     * @brief Creates the control server.
     *
     * The server does not listen until IControlServer::Start().
     * @pre Whatever @p handler_factory references outlives the returned server.
     */
    virtual ControlServerResult CreateControlServer(
        std::unique_ptr<control_plane::IHandlerChainFactory> handler_factory,
        const config::IPCConfig& ipc_config,
        ipc::message_passing::AuthorizationCallback authorization,
        ipc::message_passing::DisconnectCleanupCallback cleanup_callback) = 0;

  protected:
    IDaemonComponentFactory() = default;
};

/**
 * @brief Production factory: the configuration file, ProviderManagerFactory and the message-passing server.
 */
class DaemonComponentFactory final : public IDaemonComponentFactory
{
  public:
    bool ParseConfig(config::Config& config) override;

    ProviderManagerResult CreateProviderManager(config::Config& config) override;

    ControlServerResult CreateControlServer(std::unique_ptr<control_plane::IHandlerChainFactory> handler_factory,
                                            const config::IPCConfig& ipc_config,
                                            ipc::message_passing::AuthorizationCallback authorization,
                                            ipc::message_passing::DisconnectCleanupCallback cleanup_callback) override;
};

}  // namespace score::crypto::daemon

#endif  // SCORE_CRYPTO_SRC_DAEMON_SRC_DAEMON_COMPONENT_FACTORY_HPP
