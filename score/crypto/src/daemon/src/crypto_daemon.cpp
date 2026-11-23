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

#include "score/crypto/src/daemon/control_plane/basic_handler_chain_factory.hpp"
#include "score/crypto/src/daemon/src/disconnect_cleanup_callback.hpp"

#include "score/concurrency/interruptible_wait.h"
#include "score/mw/log/logging.h"

#include <cstdlib>
#include <utility>

namespace score::crypto::daemon
{

CryptoDaemon::CryptoDaemon(std::unique_ptr<IDaemonComponentFactory> factory) : m_factory{std::move(factory)} {}

CryptoDaemon::~CryptoDaemon() noexcept
{
    StopServer();
}

std::int32_t CryptoDaemon::Initialize(const score::mw::lifecycle::ApplicationContext& /*context*/)
{
    // No file on the default paths leaves every section absent.
    // A named but missing file, or an invalid one, stops startup.
    if (!m_factory->ParseConfig(m_config))
    {
        score::mw::log::LogError() << "Failed to load crypto stack configuration; refusing to start";
        return EXIT_FAILURE;
    }

    auto provider_manager_result = m_factory->CreateProviderManager(m_config);
    if (!provider_manager_result.has_value())
    {
        score::mw::log::LogError() << "Failed to create provider manager"
                                   << " (error code: " << static_cast<int>(provider_manager_result.error()) << ")";
        return EXIT_FAILURE;
    }
    m_provider_manager = std::move(provider_manager_result).value();

    m_data_manager = std::make_shared<data_manager::DataManager>();

    // An absent key section yields an empty config.
    // The module decides what that means for its operations.
    m_key_management_module =
        key_management::KeyManagementModule::Create(m_data_manager, m_provider_manager, m_config.GetKeyConfig());
    const auto key_management_service =
        m_key_management_module ? m_key_management_module->GetService() : key_management::KeyManagementService::Sptr{};

    auto handler_factory = std::make_unique<control_plane::BasicHandlerChainFactory>(
        m_data_manager, m_provider_manager, m_config, key_management_service);

    // TODO: Implement proper authorization callback for the control server.
    ipc::message_passing::AuthorizationCallback authorization = [](std::uint32_t, std::uint32_t) {
        return score::crypto::Expected<bool, common::DaemonErrorCode>{true};
    };
    auto cleanup_callback = detail::MakeDisconnectCleanupCallback(m_data_manager, key_management_service);

    auto server_result = m_factory->CreateControlServer(
        std::move(handler_factory), m_config.GetIPCConfig(), std::move(authorization), std::move(cleanup_callback));
    if (!server_result.has_value())
    {
        score::mw::log::LogError() << "Failed to create crypto control server"
                                   << " (error code: " << static_cast<int>(server_result.error()) << ")";
        return EXIT_FAILURE;
    }
    auto server = std::move(server_result).value();

    // Start is synchronous: a successful result means that the server is listening.
    const auto start_result = server->Start();
    if (!start_result.has_value())
    {
        score::mw::log::LogError() << "Failed to start crypto control server"
                                   << " (error code: " << static_cast<int>(start_result.error()) << ")";
        return EXIT_FAILURE;
    }
    m_server = std::move(server);
    return EXIT_SUCCESS;
}

std::int32_t CryptoDaemon::Run(const score::cpp::stop_token& token)
{
    if (m_server == nullptr)
    {
        score::mw::log::LogError() << "Crypto control server is not running; Initialize() did not succeed";
        return EXIT_FAILURE;
    }

    score::concurrency::wait_until_stop_requested(token);

    score::mw::log::LogDebug() << "Termination requested, shutting down daemon...";
    StopServer();
    return EXIT_SUCCESS;
}

void CryptoDaemon::StopServer() noexcept
{
    if (m_server == nullptr)
    {
        return;
    }
    m_server->Stop();
    m_server->WaitForTermination();
    m_server.reset();
}

}  // namespace score::crypto::daemon
