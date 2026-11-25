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

#ifndef SCORE_CRYPTO_SRC_DAEMON_SRC_CRYPTO_DAEMON_HPP
#define SCORE_CRYPTO_SRC_DAEMON_SRC_CRYPTO_DAEMON_HPP

#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/control_plane/i_control_server.h"
#include "score/crypto/src/daemon/data_manager/data_manager.hpp"
#include "score/crypto/src/daemon/key_management/key_management_module.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"
#include "score/crypto/src/daemon/src/daemon_component_factory.hpp"

#include "score/mw/lifecycle/application.h"

#include <cstdint>
#include <memory>

namespace score::crypto::daemon
{

/**
 * @brief The crypto daemon as a lifecycle application, run by score::mw::lifecycle::run_application.
 *
 * Initialize() builds the components and starts the control server.
 * The lifecycle manager reports kRunning only after Initialize() succeeds, so the report means clients can connect.
 * Run() serves until the stop token fires on SIGTERM, then stops the server.
 */
class CryptoDaemon final : public score::mw::lifecycle::Application
{
  public:
    /// @pre @p factory is not null.
    explicit CryptoDaemon(std::unique_ptr<IDaemonComponentFactory> factory);

    /// @brief Stops the control server if Initialize() started it and Run() did not stop it.
    ~CryptoDaemon() noexcept override;

    CryptoDaemon(const CryptoDaemon&) = delete;
    CryptoDaemon& operator=(const CryptoDaemon&) = delete;
    CryptoDaemon(CryptoDaemon&&) = delete;
    CryptoDaemon& operator=(CryptoDaemon&&) = delete;

    /**
     * @brief Parses the configuration, builds the providers and key management, and starts the control server.
     * @return 0 once the server is listening.
     *         EXIT_FAILURE if any step fails, with no server left running.
     */
    std::int32_t Initialize(const score::mw::lifecycle::ApplicationContext& context) override;

    /**
     * @brief Blocks until @p token is stopped, then stops the control server and waits for its sessions to close.
     * @return 0 after a clean stop.
     *         EXIT_FAILURE if Initialize() did not start a server.
     */
    std::int32_t Run(const score::cpp::stop_token& token) override;

  private:
    void StopServer() noexcept;

    std::unique_ptr<IDaemonComponentFactory> m_factory;
    // The handler chain factory inside m_server holds m_config by reference, so m_server is declared after it and
    // destroyed first.
    config::Config m_config;
    std::shared_ptr<provider::ProviderManager> m_provider_manager;
    std::shared_ptr<data_manager::DataManager> m_data_manager;
    std::shared_ptr<key_management::KeyManagementModule> m_key_management_module;
    std::unique_ptr<control_plane::IControlServer> m_server;
};

}  // namespace score::crypto::daemon

#endif  // SCORE_CRYPTO_SRC_DAEMON_SRC_CRYPTO_DAEMON_HPP
