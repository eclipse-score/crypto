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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PROVIDER_CAPABILITY_QUERY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PROVIDER_CAPABILITY_QUERY_HPP

#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/common/context/i_mediator_query.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/provider/i_provider.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace score::crypto::daemon::provider
{

/// @brief Initialized providers of @p provider_manager, ordered by id.
///
/// Leaves out providers that are not initialized and never tries to initialize one.
/// @param provider_manager Registered providers; may be null, in which case the result is empty.
[[nodiscard]] std::vector<std::shared_ptr<IProvider>> InitializedProviders(
    const ProviderManager::Sptr& provider_manager);

/// @brief Names of the capability operations at least one of @p providers accepts for @p algorithm.
///
/// In reporting order (HASH, MAC, CIPHER, SIGN, VERIFY, RANDOM, GENERATE_KEY); empty if none.
[[nodiscard]] std::vector<std::string_view> CollectCapabilities(
    const std::vector<std::shared_ptr<IProvider>>& providers,
    const ::score::crypto::AlgorithmDescriptor& algorithm);

/// @brief The initialized providers and their capabilities, shared by the provider queries.
///
/// Queries read the stored snapshot rather than the providers, so a client
/// cannot make the daemon initialize providers or ask the backends (e.g.
/// PKCS#11 C_GetMechanismInfo) per request. Get() compares the ids of the
/// initialized providers with the snapshot's, reading their state only, and
/// takes a new snapshot when they differ: a provider that failed at startup
/// and was initialized later, e.g. by a context creation retry, is reported
/// from then on. Each snapshot has its own generation, which SYSTEM_CAPABILITIES
/// pages carry so that a listing never mixes two snapshots.
class ProviderCapabilitySnapshot
{
  public:
    /// @brief One initialized provider as reported to clients.
    struct Provider
    {
        common::ProviderId id{};
        std::uint8_t wire_type{};
        std::string name;
    };

    struct Data
    {
        /// Changes whenever a new snapshot is taken; wraps around.
        std::uint16_t generation{0U};
        /// Initialized providers, ordered by id.
        std::vector<Provider> providers;
        /// Capability operations per kAlgorithmCatalog row, by row index; empty if no provider accepts the row.
        std::vector<std::vector<std::string_view>> operations;
    };

    /// @param provider_manager Registered providers; may be null, in which case the snapshot is empty.
    explicit ProviderCapabilitySnapshot(ProviderManager::Sptr provider_manager);

    /// @brief The current snapshot; a new one if the initialized providers changed since the last. Thread-safe.
    [[nodiscard]] std::shared_ptr<const Data> Get() const;

  private:
    ProviderManager::Sptr m_provider_manager;
    mutable std::mutex m_mutex;
    mutable std::shared_ptr<const Data> m_data;
    mutable std::vector<common::ProviderId> m_provider_ids;
};

/// @brief Serves PROVIDER_INFO: the id, wire type and name of one registered provider.
///
/// Reads the shared ProviderCapabilitySnapshot; thread-safe.
class ProviderInfoQuery final : public common::IMediatorQuery
{
  public:
    /// @param snapshot Shared provider snapshot; may be null, in which case every request is rejected.
    explicit ProviderInfoQuery(std::shared_ptr<const ProviderCapabilitySnapshot> snapshot);

    [[nodiscard]] bool Handle(const control_plane::protocol::ControlRequest& request,
                              const control_plane::protocol::SingleOperationRequest& operation,
                              control_plane::protocol::OperationResponseBuilder& responseBuilder) override;

  private:
    std::shared_ptr<const ProviderCapabilitySnapshot> m_snapshot;
};

/// @brief Serves QUERY_CAPABILITIES: the operations the registered providers accept for one algorithm.
///
/// Reads the shared ProviderCapabilitySnapshot; thread-safe.
class AlgorithmCapabilitiesQuery final : public common::IMediatorQuery
{
  public:
    /// @param snapshot Shared provider snapshot; may be null, in which case no operation is reported.
    explicit AlgorithmCapabilitiesQuery(std::shared_ptr<const ProviderCapabilitySnapshot> snapshot);

    [[nodiscard]] bool Handle(const control_plane::protocol::ControlRequest& request,
                              const control_plane::protocol::SingleOperationRequest& operation,
                              control_plane::protocol::OperationResponseBuilder& responseBuilder) override;

  private:
    std::shared_ptr<const ProviderCapabilitySnapshot> m_snapshot;
};

/// @brief Serves SYSTEM_CAPABILITIES: every registered provider and every catalog algorithm one of them accepts.
///
/// Reads the shared ProviderCapabilitySnapshot; thread-safe.
class SystemCapabilitiesQuery final : public common::IMediatorQuery
{
  public:
    /// @param snapshot Shared provider snapshot; may be null, in which case no provider is reported.
    explicit SystemCapabilitiesQuery(std::shared_ptr<const ProviderCapabilitySnapshot> snapshot);

    [[nodiscard]] bool Handle(const control_plane::protocol::ControlRequest& request,
                              const control_plane::protocol::SingleOperationRequest& operation,
                              control_plane::protocol::OperationResponseBuilder& responseBuilder) override;

  private:
    std::shared_ptr<const ProviderCapabilitySnapshot> m_snapshot;
};

}  // namespace score::crypto::daemon::provider

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PROVIDER_CAPABILITY_QUERY_HPP
