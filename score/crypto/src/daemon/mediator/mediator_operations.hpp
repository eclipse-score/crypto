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

#ifndef SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_MEDIATOR_OPERATIONS_HPP
#define SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_MEDIATOR_OPERATIONS_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string_view>

#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"

namespace score::crypto::daemon::mediator::operations
{

/// @brief Identifies the shared memory transport backend used for a region.
///
/// The daemon returns this in the SHM_SETUP response (param[3]) so the
/// client knows how to open and map the shared memory region.
enum class ShmTransportType : std::uint8_t
{
    kPosixNamed = 0,
    kTypedRegion = 1,
};

/// @brief Wire sentinel: indicates transport type was not included in the response (backward compat).
inline constexpr std::uint64_t SHM_WIRE_TRANSPORT_TYPE_ABSENT = 0xFFU;

inline constexpr std::uint64_t SHM_WIRE_PROVIDER_TYPE_ABSENT = 0xFFU;

inline constexpr std::uint64_t SHM_WIRE_PROVIDER_ID_UNBOUND = 0U;

using OperationAction = common::OperationAction;

/// @brief ProviderType values on the wire, shared by requests (CTX_CREATE and the
/// key-management context) and replies (PROVIDER_INFO, SYSTEM_CAPABILITIES).
///
/// They equal the public ProviderType enumerator positions; the client checks
/// that with static_asserts in crypto_context_impl.cpp.
namespace provider_type_wire
{
inline constexpr std::uint8_t kDefault = 0U;
inline constexpr std::uint8_t kHardware = 1U;
inline constexpr std::uint8_t kSoftware = 2U;
inline constexpr std::uint8_t kHardwarePreferred = 3U;
inline constexpr std::uint8_t kSoftwarePreferred = 4U;
}  // namespace provider_type_wire

/// @brief Encode a registered provider's classification for PROVIDER_INFO and SYSTEM_CAPABILITIES.
/// @return kHardware or kSoftware; kDefault for any other or no classification.
[[nodiscard]] inline constexpr std::uint8_t EncodeProviderType(
    const std::optional<common::CryptoProviderType> type) noexcept
{
    if (type == common::CryptoProviderType::HARDWARE)
    {
        return provider_type_wire::kHardware;
    }
    if (type == common::CryptoProviderType::SOFTWARE)
    {
        return provider_type_wire::kSoftware;
    }
    return provider_type_wire::kDefault;
}

// ============================================================================
// Common Mediator Operations
// ============================================================================

// CTX_CREATE
// Request:  data_node_id = connection_id (parent node),
//           param[0]: string — handler context type (e.g. "HASH" or "CERT:...")
//           param[1]: string — algorithm name (e.g. "SHA256", "SHA512")
//           param[2]: optional uint8 — provider type preference (defaults to DEFAULT)
//           param[3]: optional uint64_t — node_id of key resource (CryptoResourceId.id)
//           param[4]: optional uint8 — common::ContextMode (keyed contexts)
//           param[5]: optional uint8 — CipherPadding (cipher contexts)
//           param[6]: optional uint8 — SignatureInputMode (sign/verify contexts; param[5] is no-param)
// Capability routing: a recognized scope uses capability-based selection when the provider
// preference is DEFAULT. Explicit provider preferences and key-bound selection are still
// checked against the scope's required capability. Unrecognized or absent scopes add no
// capability constraint and follow existing provider selection rules (provider-type
// preference or key affinity). The full context type is passed to the handler factory unchanged.
// Response: status_code (SUCCESS/error)
//           uint64_t — daemon-assigned context_id (DataNodeId)
// Effect:   Creates cryptographic context, initializes handler with specified algorithm
inline constexpr OperationAction CTX_CREATE = 1;

// Stable CTX_CREATE parameter positions. Handler-specific extensions may use
// later positions; the mediator validates only the common prefix.
inline constexpr std::size_t CTX_PARAM_HANDLER_TYPE = 0U;
inline constexpr std::size_t CTX_PARAM_ALGORITHM = 1U;
inline constexpr std::size_t CTX_PARAM_PROVIDER_TYPE = 2U;
inline constexpr std::size_t CTX_PARAM_KEY_NODE_ID = 3U;
inline constexpr std::size_t CTX_PARAM_OPERATION_MODE = 4U;
inline constexpr std::size_t CTX_PARAM_CIPHER_PADDING = 5U;

/// @brief Defensive upper bound for malformed CTX_CREATE requests.
///
/// This is intentionally larger than the common prefix so handlers can add
/// opaque parameters without requiring mediator changes.
inline constexpr std::size_t CTX_MAX_PARAMETER_COUNT = 10U;

// CTX_CLOSE
// Request:  data_node_id = context_id (the context to close),
//           no operation parameters
// Response: status_code (SUCCESS)
//           no output parameters
// Effect:   Deletes the context node from DataManager
inline constexpr OperationAction CTX_CLOSE = 2;

// RESOURCE_RESOLVE
// Request:  data_node_id = connection_id,
//           param[0]: string — application-defined resource name (e.g., "HMAC_SHA256_IntegrationTestKey")
//           param[1]: uint8  — ResourceType enum value (e.g., 1 = kKeySlot)
// Response: status_code (SUCCESS/error)
//           param[0]: uint64 — daemon-assigned resource id
//           param[1]: uint8  — ResourceType enum value
//           param[2]: bool  — True if resource is persistent, false if ephemeral
//           param[3]: uint16 — primary_provider id
// Effect:   Resolves a named resource to a daemon-scoped CryptoResourceId.
//           Access control (uid-based) is enforced during resolution.
inline constexpr OperationAction RESOLVE_RESOURCE = 3;

inline control_plane::protocol::OperationIdentifier CreateContext()
{
    return control_plane::protocol::OperationIdentifier{.operationActor = common::actors::OP_ACTOR_MEDIATOR,
                                                        .operationAction = operations::CTX_CREATE};
}
inline control_plane::protocol::OperationIdentifier CloseContext()
{
    return control_plane::protocol::OperationIdentifier{.operationActor = common::actors::OP_ACTOR_MEDIATOR,
                                                        .operationAction = operations::CTX_CLOSE};
}
inline control_plane::protocol::OperationIdentifier ResolveResource()
{
    return control_plane::protocol::OperationIdentifier{.operationActor = common::actors::OP_ACTOR_MEDIATOR,
                                                        .operationAction = operations::RESOLVE_RESOURCE};
}

// SHM_SETUP
// Request:  uint64_t — size (bytes; 0 for pool — daemon uses deployment config size)
//           uint64_t — wire ProviderType hint (SHM_WIRE_PROVIDER_TYPE_ABSENT if absent)
//           uint64_t — numeric provider id hint (SHM_WIRE_PROVIDER_ID_UNBOUND if absent)
//           uint64_t — is_pool (0 = bulk object, 1 = pool object)
//
// Response (is_pool=0 — bulk):
//           status_code (SUCCESS)
//           param[0]: uint64_t   — node_id
//           param[1]: uint64_t   — actual_size
//           param[2]: DataBuffer — wire_token
//           param[3]: uint64_t   — transport_type
//
// Response (is_pool=1 — pool, extends bulk layout at params [4..5]):
//           same as is_pool=0 PLUS:
//           param[4]: uint64_t — pool_slot_size
//           param[5]: uint64_t — total_quota
inline constexpr OperationAction SHM_SETUP = 4;

// SHM_SETUP response parameter indices (wire protocol contract shared by daemon and client).
inline constexpr std::size_t SHM_PARAM_NODE_ID = 0;
inline constexpr std::size_t SHM_PARAM_SIZE = 1;
inline constexpr std::size_t SHM_PARAM_TOKEN = 2;
inline constexpr std::size_t SHM_PARAM_TRANSPORT = 3;
inline constexpr std::size_t SHM_PARAM_SLOT_SIZE = 4;
inline constexpr std::size_t SHM_PARAM_TOTAL_QUOTA = 5;

// SHM_DESTROY_OBJECT
// Request:  uint64_t — node_id
// Response: status_code (SUCCESS/error)
//           no output parameters
// Effect:   Unmaps and unlinks the SHM object, removes it from the daemon registry.
inline constexpr OperationAction SHM_DESTROY_OBJECT = 5;

/// @brief Operation actions the mediator implements itself. A mediator query is never registered
/// for one of these.
inline constexpr std::array<OperationAction, 5U> kBuiltInActions{CTX_CREATE,
                                                                 CTX_CLOSE,
                                                                 RESOLVE_RESOURCE,
                                                                 SHM_SETUP,
                                                                 SHM_DESTROY_OBJECT};

inline control_plane::protocol::OperationIdentifier CreateShmObject()
{
    return control_plane::protocol::OperationIdentifier{.operationActor = common::actors::OP_ACTOR_MEDIATOR,
                                                        .operationAction = operations::SHM_SETUP};
}
inline control_plane::protocol::OperationIdentifier DestroyShmObject()
{
    return control_plane::protocol::OperationIdentifier{.operationActor = common::actors::OP_ACTOR_MEDIATOR,
                                                        .operationAction = operations::SHM_DESTROY_OBJECT};
}

// ============================================================================
// Provider and capability queries
//
// Served by the provider subsystem's mediator queries, which
// provider::ProviderQueryRegistrar registers; the mediator implements none of them itself.
// ============================================================================

// PROVIDER_INFO
// Request:  uint64 — provider id
// Response: status_code (SUCCESS / kInvalidArgument for an unknown id)
//           param[0]: uint16     — provider id
//           param[1]: uint8      — wire ProviderType (0 = default, 1 = hardware, 2 = software)
//           param[2]: DataBuffer — provider name (UTF-8, not NUL-terminated)
inline constexpr OperationAction PROVIDER_INFO = 9;

// QUERY_CAPABILITIES
// Request:  string — algorithm name, as in the algorithm catalog
// Response: status_code (SUCCESS)
//           param[0]: uint16 — operation count N; 0 if no provider accepts this name
//           N times:  DataBuffer operation name (see capability_operations)
inline constexpr OperationAction QUERY_CAPABILITIES = 10;

// SYSTEM_CAPABILITIES
// Request:  param[0]: uint16 — cursor; 0 for the first page, then the cursor
//                     returned by the previous page
//           param[1]: uint16 — generation returned by the first page; ignored
//                     when the cursor is 0
// Response: status_code (SUCCESS)
//           param[0]: uint16 — next cursor, or kSystemCapabilitiesDone after the last page
//           param[1]: uint16 — generation of the snapshot this page was cut from
//           then:     uint16 — provider count P
//           P times:  uint16 provider id, uint8 wire ProviderType, DataBuffer name
//           then:     uint16 — algorithm count A
//           A times:  DataBuffer algorithm name (UTF-8, not NUL-terminated),
//                     uint16 operation count N (never 0),
//                     N times DataBuffer operation name (see capability_operations)
// Effect:   Lists the providers and every catalog algorithm at least one of
//           them accepts, in catalog order. One reply must fit the IPC frame,
//           so the list is split into pages: the cursor walks the providers
//           first, then the catalog rows, and each page holds as many entries
//           as fit common::kMaxResponsePayloadBytes. All pages of a listing
//           come from one snapshot, identified by its generation.
// Errors:   kInvalidArgument for a missing or out-of-range cursor or generation;
//           kInvalidOperation if the providers changed since the first page
//           (the generation is stale): start again from cursor 0;
//           kInsufficientBufferSize if a single entry does not fit one page.
inline constexpr OperationAction SYSTEM_CAPABILITIES = 11;

/// Next-cursor value SYSTEM_CAPABILITIES returns after the last page.
inline constexpr std::uint16_t kSystemCapabilitiesDone = 0U;

/// Operation names reported by QUERY_CAPABILITIES and SYSTEM_CAPABILITIES.
///
/// An algorithm reports the context type (common::context_types, e.g. "HASH",
/// "SIGN") of every context a provider would create for it, followed by
/// kGenerateKey if a provider generates keys for it. The client passes the
/// names through to AlgorithmCapabilities::operations unchanged, so a new
/// operation needs no client change.
namespace capability_operations
{
inline constexpr std::string_view kGenerateKey = "GENERATE_KEY";
}  // namespace capability_operations

inline control_plane::protocol::OperationIdentifier GetProviderInfo()
{
    return control_plane::protocol::OperationIdentifier{.operationActor = common::actors::OP_ACTOR_MEDIATOR,
                                                        .operationAction = operations::PROVIDER_INFO};
}
inline control_plane::protocol::OperationIdentifier QueryCapabilities()
{
    return control_plane::protocol::OperationIdentifier{.operationActor = common::actors::OP_ACTOR_MEDIATOR,
                                                        .operationAction = operations::QUERY_CAPABILITIES};
}
inline control_plane::protocol::OperationIdentifier QuerySystemCapabilities()
{
    return control_plane::protocol::OperationIdentifier{.operationActor = common::actors::OP_ACTOR_MEDIATOR,
                                                        .operationAction = operations::SYSTEM_CAPABILITIES};
}

// Starting point for custom OPs
inline constexpr OperationAction CUSTOM_OP_START = 1 << (std::numeric_limits<OperationAction>::digits - 1);

}  // namespace score::crypto::daemon::mediator::operations

#endif  // SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_MEDIATOR_OPERATIONS_HPP
