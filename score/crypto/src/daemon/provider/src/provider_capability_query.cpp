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

#include "score/crypto/src/daemon/provider/provider_capability_query.hpp"

#include "score/crypto/common/error_domain.hpp"
#include "score/crypto/src/daemon/common/context/context_types.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_management_operations.hpp"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/i_crypto_handler_factory.hpp"
#include "score/crypto/types/common.hpp"
#include "score/mw/log/logging.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <limits>
#include <utility>
#include <variant>

namespace score::crypto::daemon::provider
{

namespace
{

namespace protocol = control_plane::protocol;
namespace mediator_ops = mediator::operations;

std::vector<std::uint8_t> ToBytes(std::string_view text)
{
    return std::vector<std::uint8_t>(text.begin(), text.end());
}

// SYSTEM_CAPABILITIES reports a subset of the catalog, and provider names are
// limited at registration; both must fit the public structs the client fills.
static_assert(std::size(score::crypto::kAlgorithmCatalog) <= SystemCapabilities::kMaxAlgorithms,
              "SystemCapabilities cannot hold every catalog algorithm");
static_assert(common::kMaxProviderNameLength == decltype(ProviderInfo::name)::capacity(),
              "provider name limit differs from ProviderInfo::name capacity");

constexpr bool AllCatalogNamesFitAlgorithmId() noexcept
{
    for (const auto& row : score::crypto::kAlgorithmCatalog)
    {
        if (row.name.size() > AlgorithmId::capacity())
        {
            return false;
        }
    }
    return true;
}
static_assert(AllCatalogNamesFitAlgorithmId(), "catalog algorithm name exceeds AlgorithmId capacity");

/// Context types reported as capability operations, in reporting order.
constexpr std::array<std::string_view, 6U> kCapabilityContexts{common::context_types::kHash,
                                                               common::context_types::kMac,
                                                               common::context_types::kCipher,
                                                               common::context_types::kSign,
                                                               common::context_types::kVerify,
                                                               common::context_types::kRandom};

/// Key factory operations reported as capability operations, in reporting order.
constexpr std::array<std::pair<common::OperationAction, std::string_view>, 1U> kCapabilityKeyOperations{
    {{key_management::operations::KEY_GENERATE, mediator_ops::capability_operations::kGenerateKey}}};

constexpr bool FitsOperationName(std::string_view name) noexcept
{
    return name.size() <= decltype(AlgorithmCapabilities::operations)::value_type::capacity();
}

constexpr bool AllOperationNamesFit() noexcept
{
    for (const auto name : kCapabilityContexts)
    {
        if (!FitsOperationName(name))
        {
            return false;
        }
    }
    for (const auto& entry : kCapabilityKeyOperations)
    {
        if (!FitsOperationName(entry.second))
        {
            return false;
        }
    }
    return true;
}

// The client copies the names into AlgorithmCapabilities without truncating.
static_assert(std::size(kCapabilityContexts) + std::size(kCapabilityKeyOperations) <=
                  AlgorithmCapabilities::kMaxOperations,
              "AlgorithmCapabilities cannot hold every capability operation");
static_assert(AllOperationNamesFit(), "capability operation name exceeds AlgorithmCapabilities::operations capacity");

/// Estimated wire bytes one response parameter adds beyond its payload: union
/// tag, offset slot, table header and vector length in the FlatBuffer encoding.
constexpr std::size_t kParameterOverheadBytes = 24U;

constexpr std::size_t ParameterCost(std::size_t payload_bytes) noexcept
{
    return payload_bytes + kParameterOverheadBytes;
}

using mediator_ops::kSystemCapabilitiesDone;

// The cursor is a uint16 on the wire and 0 marks the end, which is never a
// position after a non-empty page.
static_assert(SystemCapabilities::kMaxProviders + std::size(score::crypto::kAlgorithmCatalog) <
                  std::numeric_limits<std::uint16_t>::max(),
              "SYSTEM_CAPABILITIES cursor does not fit uint16");

/// Appends an operation count and the operation names to @p response.
void AppendOperations(protocol::OperationResponseBuilder& response, const std::vector<std::string_view>& names)
{
    response.return_value_uint16(static_cast<std::uint16_t>(names.size()));
    for (const auto name : names)
    {
        response.return_value_data_buffer_out(ToBytes(name));
    }
}

std::shared_ptr<const ProviderCapabilitySnapshot::Data> Snapshot(
    const std::shared_ptr<const ProviderCapabilitySnapshot>& snapshot)
{
    return (snapshot == nullptr) ? ProviderCapabilitySnapshot{nullptr}.Get() : snapshot->Get();
}

std::size_t CatalogIndex(const ::score::crypto::AlgorithmDescriptor& algorithm)
{
    const auto* const row = std::find_if(std::begin(score::crypto::kAlgorithmCatalog),
                                         std::end(score::crypto::kAlgorithmCatalog),
                                         [&algorithm](const auto& entry) {
                                             return entry.id == algorithm.id;
                                         });
    return static_cast<std::size_t>(std::distance(std::begin(score::crypto::kAlgorithmCatalog), row));
}

}  // namespace

std::vector<std::shared_ptr<IProvider>> InitializedProviders(const ProviderManager::Sptr& provider_manager)
{
    std::vector<std::shared_ptr<IProvider>> providers;
    if (provider_manager == nullptr)
    {
        return providers;
    }
    for (const auto id : provider_manager->InitializedProviderIds())
    {
        // Already initialized, so GetProvider() does not initialize it again.
        if (auto provider = provider_manager->GetProvider(id))
        {
            providers.push_back(std::move(provider));
        }
    }
    return providers;
}

std::vector<std::string_view> CollectCapabilities(const std::vector<std::shared_ptr<IProvider>>& providers,
                                                  const ::score::crypto::AlgorithmDescriptor& algorithm)
{
    std::array<bool, std::size(kCapabilityContexts)> accepted{};
    std::array<bool, std::size(kCapabilityKeyOperations)> key_accepted{};
    for (const auto& provider : providers)
    {
        if (const auto factory = provider->GetCryptoHandlerFactory())
        {
            for (std::size_t i = 0U; i < std::size(kCapabilityContexts); ++i)
            {
                accepted.at(i) = accepted.at(i) ||
                                 factory->IsAlgorithmSupported(common::HandlerId{kCapabilityContexts.at(i)}, algorithm);
            }
        }
        if (const auto key_factory = provider->GetKeyFactory())
        {
            for (std::size_t i = 0U; i < std::size(kCapabilityKeyOperations); ++i)
            {
                key_accepted.at(i) = key_accepted.at(i) ||
                                     key_factory->IsOperationSupported(kCapabilityKeyOperations.at(i).first, algorithm);
            }
        }
    }

    std::vector<std::string_view> result;
    for (std::size_t i = 0U; i < std::size(kCapabilityContexts); ++i)
    {
        if (accepted.at(i))
        {
            result.push_back(kCapabilityContexts.at(i));
        }
    }
    for (std::size_t i = 0U; i < std::size(kCapabilityKeyOperations); ++i)
    {
        if (key_accepted.at(i))
        {
            result.push_back(kCapabilityKeyOperations.at(i).second);
        }
    }
    return result;
}

ProviderCapabilitySnapshot::ProviderCapabilitySnapshot(ProviderManager::Sptr provider_manager)
    : m_provider_manager{std::move(provider_manager)}
{
}

std::shared_ptr<const ProviderCapabilitySnapshot::Data> ProviderCapabilitySnapshot::Get() const
{
    const auto ids = (m_provider_manager == nullptr) ? std::vector<common::ProviderId>{}
                                                     : m_provider_manager->InitializedProviderIds();
    std::lock_guard<std::mutex> lock(m_mutex);
    if ((m_data != nullptr) && (ids == m_provider_ids))
    {
        return m_data;
    }

    auto data = std::make_shared<Data>();
    data->generation = static_cast<std::uint16_t>((m_data == nullptr) ? 1U : (m_data->generation + 1U));
    const auto providers = InitializedProviders(m_provider_manager);
    for (const auto& provider : providers)
    {
        const auto& name = provider->GetProviderName();
        data->providers.push_back(Provider{provider->GetProviderId(),
                                           mediator_ops::EncodeProviderType(m_provider_manager->GetProviderType(name)),
                                           std::string{name}});
    }
    data->operations.reserve(std::size(score::crypto::kAlgorithmCatalog));
    for (const auto& row : score::crypto::kAlgorithmCatalog)
    {
        data->operations.push_back(CollectCapabilities(providers, row));
    }
    m_provider_ids = ids;
    m_data = std::move(data);
    return m_data;
}

ProviderInfoQuery::ProviderInfoQuery(std::shared_ptr<const ProviderCapabilitySnapshot> snapshot)
    : m_snapshot{std::move(snapshot)}
{
}

bool ProviderInfoQuery::Handle(const protocol::ControlRequest& /*request*/,
                               const protocol::SingleOperationRequest& operation,
                               protocol::OperationResponseBuilder& responseBuilder)
{
    const auto* id_param =
        operation.parameters.empty() ? nullptr : std::get_if<std::uint64_t>(&operation.parameters[0]);
    const auto data = Snapshot(m_snapshot);
    const auto& providers = data->providers;
    const auto provider = (id_param == nullptr)
                              ? providers.end()
                              : std::find_if(providers.begin(), providers.end(), [id = *id_param](const auto& entry) {
                                    return entry.id == id;
                                });
    if (provider == providers.end())
    {
        responseBuilder.operation(operation.operationId).return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
        return false;
    }

    responseBuilder.operation(operation.operationId)
        .return_value_uint16(provider->id)
        .return_value_uint8(provider->wire_type)
        .return_value_data_buffer_out(ToBytes(provider->name))
        .return_success();
    return true;
}

AlgorithmCapabilitiesQuery::AlgorithmCapabilitiesQuery(std::shared_ptr<const ProviderCapabilitySnapshot> snapshot)
    : m_snapshot{std::move(snapshot)}
{
}

bool AlgorithmCapabilitiesQuery::Handle(const protocol::ControlRequest& /*request*/,
                                        const protocol::SingleOperationRequest& operation,
                                        protocol::OperationResponseBuilder& responseBuilder)
{
    const auto* name_param =
        operation.parameters.empty() ? nullptr : std::get_if<std::string_view>(&operation.parameters[0]);
    if (name_param == nullptr)
    {
        responseBuilder.operation(operation.operationId).return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
        return false;
    }

    // An empty name asks for the default generator, as it does when a RANDOM
    // context is created. A name the catalog does not know is served by no provider.
    const auto algorithm = name_param->empty()
                               ? score::crypto::GetAlgorithmDescriptor(score::crypto::Algorithm::kCtrDrbg)
                               : score::crypto::GetAlgorithmDescriptor(*name_param);
    auto& response = responseBuilder.operation(operation.operationId);
    const auto data = Snapshot(m_snapshot);
    const auto& operations = data->operations;
    const auto row = algorithm.has_value() ? CatalogIndex(algorithm.value()) : operations.size();
    AppendOperations(response, (row < operations.size()) ? operations[row] : std::vector<std::string_view>{});
    response.return_success();
    return true;
}

SystemCapabilitiesQuery::SystemCapabilitiesQuery(std::shared_ptr<const ProviderCapabilitySnapshot> snapshot)
    : m_snapshot{std::move(snapshot)}
{
}

bool SystemCapabilitiesQuery::Handle(const protocol::ControlRequest& /*request*/,
                                     const protocol::SingleOperationRequest& operation,
                                     protocol::OperationResponseBuilder& responseBuilder)
{
    const auto* cursor_param =
        (operation.parameters.size() < 2U) ? nullptr : std::get_if<std::uint16_t>(&operation.parameters[0]);
    const auto* generation_param =
        (operation.parameters.size() < 2U) ? nullptr : std::get_if<std::uint16_t>(&operation.parameters[1]);
    if ((cursor_param == nullptr) || (generation_param == nullptr))
    {
        responseBuilder.operation(operation.operationId).return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
        return false;
    }

    const auto data = Snapshot(m_snapshot);
    const auto& snapshot = *data;
    // A later page must come from the snapshot the first page was cut from.
    if ((*cursor_param != 0U) && (*generation_param != snapshot.generation))
    {
        responseBuilder.operation(operation.operationId)
            .return_error(score::crypto::CryptoErrorCode::kInvalidOperation);
        return false;
    }
    const auto& providers = snapshot.providers;
    if (providers.size() > SystemCapabilities::kMaxProviders)
    {
        score::mw::log::LogError() << "[PROVIDER_QUERY] SYSTEM_CAPABILITIES: " << providers.size()
                                   << " providers exceed the client limit of " << SystemCapabilities::kMaxProviders;
        responseBuilder.operation(operation.operationId)
            .return_error(score::crypto::CryptoErrorCode::kInsufficientBufferSize);
        return false;
    }

    // The cursor walks the providers first, then the catalog rows.
    const std::size_t total = providers.size() + std::size(score::crypto::kAlgorithmCatalog);
    const std::size_t cursor = *cursor_param;
    if (cursor > total)
    {
        responseBuilder.operation(operation.operationId).return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
        return false;
    }

    // Next cursor, generation, provider count and algorithm count are always sent.
    std::size_t budget = common::kMaxResponsePayloadBytes - (4U * ParameterCost(sizeof(std::uint16_t)));
    std::vector<const ProviderCapabilitySnapshot::Provider*> page_providers;
    std::vector<std::pair<std::string_view, const std::vector<std::string_view>*>> page_algorithms;
    std::size_t next = cursor;
    for (; next < total; ++next)
    {
        std::size_t cost = 0U;
        if (next < providers.size())
        {
            cost = ParameterCost(sizeof(std::uint16_t)) + ParameterCost(sizeof(std::uint8_t)) +
                   ParameterCost(providers[next].name.size());
        }
        else
        {
            const auto row_index = next - providers.size();
            const auto& row = score::crypto::kAlgorithmCatalog[row_index];
            const auto& ops = snapshot.operations[row_index];
            if (!ops.empty())
            {
                cost = ParameterCost(row.name.size()) + ParameterCost(sizeof(std::uint16_t));
                for (const auto op : ops)
                {
                    cost += ParameterCost(op.size());
                }
                if (cost <= budget)
                {
                    page_algorithms.emplace_back(row.name, &ops);
                }
            }
        }
        if (cost > budget)
        {
            break;
        }
        budget -= cost;
        if (next < providers.size())
        {
            page_providers.push_back(&providers[next]);
        }
    }
    if ((next == cursor) && (next < total))
    {
        score::mw::log::LogError() << "[PROVIDER_QUERY] SYSTEM_CAPABILITIES: entry " << next
                                   << " does not fit one response";
        responseBuilder.operation(operation.operationId)
            .return_error(score::crypto::CryptoErrorCode::kInsufficientBufferSize);
        return false;
    }

    auto& response = responseBuilder.operation(operation.operationId);
    response.return_value_uint16(static_cast<std::uint16_t>((next == total) ? kSystemCapabilitiesDone : next));
    response.return_value_uint16(snapshot.generation);
    response.return_value_uint16(static_cast<std::uint16_t>(page_providers.size()));
    for (const auto* provider : page_providers)
    {
        response.return_value_uint16(provider->id)
            .return_value_uint8(provider->wire_type)
            .return_value_data_buffer_out(ToBytes(provider->name));
    }
    response.return_value_uint16(static_cast<std::uint16_t>(page_algorithms.size()));
    for (const auto& [name, ops] : page_algorithms)
    {
        response.return_value_data_buffer_out(ToBytes(name));
        AppendOperations(response, *ops);
    }
    response.return_success();
    return true;
}

}  // namespace score::crypto::daemon::provider
