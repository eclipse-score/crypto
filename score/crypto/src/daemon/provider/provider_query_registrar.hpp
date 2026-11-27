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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PROVIDER_QUERY_REGISTRAR_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PROVIDER_QUERY_REGISTRAR_HPP

#include "score/crypto/src/daemon/common/context/i_mediator_registrar.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"

namespace score::crypto::daemon::provider
{

/// @brief Registers the provider subsystem's mediator queries.
///
/// Adds ProviderInfoQuery, AlgorithmCapabilitiesQuery and SystemCapabilitiesQuery under
/// PROVIDER_INFO, QUERY_CAPABILITIES and SYSTEM_CAPABILITIES. The queries share the provider
/// manager; the registrar keeps nothing else.
class ProviderQueryRegistrar final : public common::IMediatorRegistrar
{
  public:
    /// @param provider_manager Registered providers the queries report on.
    explicit ProviderQueryRegistrar(ProviderManager::Sptr provider_manager);

    [[nodiscard]] bool Register(common::MediatorRegistries& registries) const override;

  private:
    ProviderManager::Sptr m_provider_manager;
};

}  // namespace score::crypto::daemon::provider

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PROVIDER_QUERY_REGISTRAR_HPP
