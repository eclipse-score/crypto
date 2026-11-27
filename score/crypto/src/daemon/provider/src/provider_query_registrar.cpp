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

#include "score/crypto/src/daemon/provider/provider_query_registrar.hpp"

#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/src/daemon/provider/provider_capability_query.hpp"

#include <memory>
#include <utility>

namespace score::crypto::daemon::provider
{

ProviderQueryRegistrar::ProviderQueryRegistrar(ProviderManager::Sptr provider_manager)
    : m_provider_manager{std::move(provider_manager)}
{
}

bool ProviderQueryRegistrar::Register(common::MediatorRegistries& registries) const
{
    namespace mediator_ops = mediator::operations;
    auto& queries = registries.mediator_queries;
    // One snapshot for all three, so they answer consistently.
    const auto snapshot = std::make_shared<const ProviderCapabilitySnapshot>(m_provider_manager);
    return queries.Register(mediator_ops::PROVIDER_INFO, std::make_shared<ProviderInfoQuery>(snapshot)) &&
           queries.Register(mediator_ops::QUERY_CAPABILITIES, std::make_shared<AlgorithmCapabilitiesQuery>(snapshot)) &&
           queries.Register(mediator_ops::SYSTEM_CAPABILITIES, std::make_shared<SystemCapabilitiesQuery>(snapshot));
}

}  // namespace score::crypto::daemon::provider
