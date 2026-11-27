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

#include "score/crypto/src/api/crypto_context_impl.hpp"

#include "score/crypto/common/error_domain.hpp"
#include "score/crypto/config/cipher_context_config.hpp"
#include "score/crypto/config/hash_context_config.hpp"
#include "score/crypto/config/key_management_context_config.hpp"
#include "score/crypto/config/mac_context_config.hpp"
#include "score/crypto/config/random_context_config.hpp"
#include "score/crypto/config/sign_context_config.hpp"
#include "score/crypto/config/verify_signature_context_config.hpp"
#include "score/crypto/contexts/src/cipher_context_impl.hpp"
#include "score/crypto/contexts/src/hash_context_impl.hpp"
#include "score/crypto/contexts/src/key_management_context_impl.hpp"
#include "score/crypto/contexts/src/mac_context_impl.hpp"
#include "score/crypto/contexts/src/random_context_impl.hpp"
#include "score/crypto/contexts/src/sign_context_impl.hpp"
#include "score/crypto/contexts/src/verify_signature_context_impl.hpp"
#include "score/crypto/src/api/provider_type_converter.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/common/context/context_mode.hpp"
#include "score/crypto/src/daemon/common/context/context_types.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/types/certificate.hpp"
#include "score/crypto/types/common.hpp"

#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/result/result.h"

#include "score/mw/log/logging.h"
#include <cstdint>

#include <memory>
#include <utility>

// Full definitions needed for Result<unique_ptr<T>> return types
#include "score/crypto/contexts/i_cipher_context.hpp"
#include "score/crypto/contexts/i_hash_context.hpp"
#include "score/crypto/contexts/i_key_management_context.hpp"
#include "score/crypto/contexts/i_mac_context.hpp"
#include "score/crypto/contexts/i_random_context.hpp"
#include "score/crypto/contexts/i_sign_context.hpp"
#include "score/crypto/contexts/i_verify_signature_context.hpp"
#include "score/crypto/objects/i_key_object.hpp"
#include "score/crypto/objects/i_key_slot_object.hpp"

#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"

#include <optional>
#include <string_view>

namespace score
{

namespace crypto
{

/// The context-type ids are owned by the daemon side, which dispatches on them.
namespace daemon_common = ::score::crypto::daemon::common;

namespace
{

// The client encodes and decodes ProviderType without the daemon headers
// (ProviderTypeConverter); both sides must agree on the values.
namespace wire = ::score::crypto::daemon::mediator::operations::provider_type_wire;
static_assert(ProviderTypeConverter::ToWireValue(ProviderType::kDefault) == wire::kDefault);
static_assert(ProviderTypeConverter::ToWireValue(ProviderType::kHardware) == wire::kHardware);
static_assert(ProviderTypeConverter::ToWireValue(ProviderType::kSoftware) == wire::kSoftware);
static_assert(ProviderTypeConverter::ToWireValue(ProviderType::kHardwarePreferred) == wire::kHardwarePreferred);
static_assert(ProviderTypeConverter::ToWireValue(ProviderType::kSoftwarePreferred) == wire::kSoftwarePreferred);
static_assert(ProviderTypeConverter::FromWireValue(wire::kSoftwarePreferred + 1U) == ProviderType::kDefault);

/// @brief Describes one CTX_CREATE call on the wire.
///
/// Wire layout is positional and shared by every context type:
///   [0] context_type, [1] algorithm, [2] provider_type (or no-param),
///   [3] key_node_id (keyed contexts only), [4] daemon_common::ContextMode,
///   [5] CipherPadding (cipher contexts only; no-param for signature contexts),
///   [6] SignatureInputMode (signature contexts only).
struct ContextCreationRequest
{
    std::string_view context_type{};
    /// Null for a context type that names no algorithm, which the daemon reads
    /// as the empty string in slot [1]. KEY:MANAGEMENT is the only such type.
    const AlgorithmId* algorithm{nullptr};
    std::optional<ProviderType> provider_type{std::nullopt};
    std::optional<std::uint64_t> key_node_id{std::nullopt};
    std::optional<daemon_common::ContextMode> mode{std::nullopt};
    std::optional<CipherPadding> padding{std::nullopt};
    std::optional<SignatureInputMode> signature_input_mode{std::nullopt};
};

/// @brief Views a wire DataBuffer as UTF-8 text.
std::string_view AsText(const std::vector<std::uint8_t>& bytes)
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast) bytes are UTF-8 text
    return std::string_view{reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

/// @brief Reads an operation count and that many operation names, starting at @p index.
///
/// Advances @p index past what was read. Returns nullopt if the parameters are
/// missing or mistyped, or if the list does not fit AlgorithmCapabilities: the
/// daemon guarantees it does, so anything else is a malformed response.
std::optional<AlgorithmCapabilities> ReadAlgorithmCapabilities(
    ::score::crypto::daemon::control_plane::protocol::ControlResponseValidator& validator,
    std::size_t& index,
    const AlgorithmId& algorithm)
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;
    const auto count = validator.getParameterAt<std::uint16_t>(0, index++);
    if (!count.has_value() || (count.value() > AlgorithmCapabilities::kMaxOperations))
    {
        return std::nullopt;
    }

    AlgorithmCapabilities result{};
    result.id = algorithm;
    for (std::uint16_t i = 0U; i < count.value(); ++i)
    {
        const auto name = validator.getParameterAt<proto::DataBufferReturn>(0, index++);
        if (!name.has_value())
        {
            return std::nullopt;
        }
        auto& operation = result.operations[result.operation_count++];
        operation = AsText(name.value());
        if (operation.truncated())
        {
            return std::nullopt;
        }
    }
    result.supported = (result.operation_count > 0U);
    return result;
}

/// @brief Builds the public provider record from PROVIDER_INFO wire values.
/// @return nullopt if @p name does not fit ProviderInfo::name; the daemon
///         rejects such names at registration, so the response is malformed.
std::optional<ProviderInfo> MakeProviderInfo(std::uint16_t id,
                                             std::uint8_t wire_type,
                                             const std::vector<std::uint8_t>& name)
{
    ProviderInfo info{};
    info.id = id;
    info.type = ProviderTypeConverter::FromWireValue(wire_type);
    info.name = AsText(name);
    if (info.name.truncated())
    {
        return std::nullopt;
    }
    return info;
}

/// @brief The cursor and snapshot generation a SYSTEM_CAPABILITIES page returns.
struct SystemCapabilitiesPosition
{
    std::uint16_t next{0U};
    std::uint16_t generation{0U};
};

/// @brief Appends one SYSTEM_CAPABILITIES page to @p result.
/// @return The next cursor and the page's generation; kInsufficientBufferSize if the providers overflow
///         SystemCapabilities (the daemon refuses more than kMaxProviders, so
///         this comes from a daemon without that check); kInternalError if the
///         page is malformed or lists more algorithms than the catalog holds.
Expected<SystemCapabilitiesPosition, CryptoErrorCode> ReadSystemCapabilitiesPage(
    ::score::crypto::daemon::control_plane::protocol::ControlResponseValidator& validator,
    SystemCapabilities& result)
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;
    std::size_t index = 0U;

    const auto next = validator.getParameterAt<std::uint16_t>(0, index++);
    const auto generation = validator.getParameterAt<std::uint16_t>(0, index++);
    const auto provider_count = validator.getParameterAt<std::uint16_t>(0, index++);
    if (!next.has_value() || !generation.has_value() || !provider_count.has_value())
    {
        return make_unexpected(CryptoErrorCode::kInternalError);
    }
    if (provider_count.value() > (SystemCapabilities::kMaxProviders - result.provider_count))
    {
        return make_unexpected(CryptoErrorCode::kInsufficientBufferSize);
    }
    for (std::uint16_t i = 0U; i < provider_count.value(); ++i)
    {
        const auto id = validator.getParameterAt<std::uint16_t>(0, index++);
        const auto type = validator.getParameterAt<std::uint8_t>(0, index++);
        const auto name = validator.getParameterAt<proto::DataBufferReturn>(0, index++);
        if (!id.has_value() || !type.has_value() || !name.has_value())
        {
            return make_unexpected(CryptoErrorCode::kInternalError);
        }
        auto info = MakeProviderInfo(id.value(), type.value(), name.value());
        if (!info.has_value())
        {
            return make_unexpected(CryptoErrorCode::kInternalError);
        }
        result.providers[result.provider_count++] = info.value();
    }

    const auto algorithm_count = validator.getParameterAt<std::uint16_t>(0, index++);
    if (!algorithm_count.has_value() ||
        (algorithm_count.value() > (SystemCapabilities::kMaxAlgorithms - result.algorithm_count)))
    {
        return make_unexpected(CryptoErrorCode::kInternalError);
    }
    for (std::uint16_t i = 0U; i < algorithm_count.value(); ++i)
    {
        const auto name = validator.getParameterAt<proto::DataBufferReturn>(0, index++);
        if (!name.has_value())
        {
            return make_unexpected(CryptoErrorCode::kInternalError);
        }
        const AlgorithmId algorithm{AsText(name.value())};
        if (algorithm.truncated())
        {
            return make_unexpected(CryptoErrorCode::kInternalError);
        }
        auto capabilities = ReadAlgorithmCapabilities(validator, index, algorithm);
        if (!capabilities.has_value() || !capabilities.value().supported)
        {
            return make_unexpected(CryptoErrorCode::kInternalError);
        }
        result.algorithms[result.algorithm_count++] = capabilities.value();
    }
    return SystemCapabilitiesPosition{next.value(), generation.value()};
}

/// How often QueryCapabilities() starts the listing again when the providers
/// change while it reads the pages.
constexpr std::size_t kSystemCapabilitiesMaxRestarts = 3U;

/// @brief Sends CTX_CREATE to the daemon and returns the new context's node id.
///
/// Centralises the request/validate/extract sequence that is identical for all
/// context types, so each factory below only has to describe its parameters and
/// wrap the resulting id in the right context implementation.
score::Result<std::uint64_t> CreateDaemonContext(
    const std::shared_ptr<score::crypto::api::control_plane::IConnection>& connection,
    const ContextCreationRequest& request,
    const std::chrono::milliseconds operation_timeout)
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;

    auto builder =
        proto::ControlRequestBuilder()
            .forDataNodeId(connection->GetConnectionNodeId())
            .operation(score::crypto::daemon::mediator::operations::CreateContext())
            .with_in_string(request.context_type)
            .with_in_string(request.algorithm != nullptr ? std::string_view{*request.algorithm} : std::string_view{});

    if (request.provider_type.has_value())
    {
        builder = builder.with_in_val_uint8(ProviderTypeConverter::ToWireValue(request.provider_type.value()));
    }
    else
    {
        builder = builder.with_no_param();
    }

    if (request.key_node_id.has_value())
    {
        builder = builder.with_in_val_uint64(request.key_node_id.value());
    }
    else
    {
        builder = builder.with_no_param();
    }

    if (request.mode.has_value())
    {
        builder = builder.with_in_val_uint8(static_cast<std::uint8_t>(request.mode.value()));
    }
    else
    {
        builder = builder.with_no_param();
    }

    if (request.padding.has_value())
    {
        builder = builder.with_in_val_uint8(static_cast<std::uint8_t>(request.padding.value()));
    }
    else
    {
        builder = builder.with_no_param();
    }

    if (request.signature_input_mode.has_value())
    {
        builder = builder.with_in_val_uint8(static_cast<std::uint8_t>(request.signature_input_mode.value()));
    }
    else
    {
        builder = builder.with_no_param();
    }

    auto control_req_result = builder.build();
    if (!control_req_result.has_value())
    {
        score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR: Failed to build CTX_CREATE request for"
                                   << request.context_type;
        return score::Result<std::uint64_t>{
            score::unexpect, MakeError(CryptoErrorCode::kContextCreationFailed, "Failed to build CTX_CREATE request")};
    }

    auto control_response_res = connection->SendRequest(control_req_result.value(), operation_timeout);

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation(score::crypto::daemon::mediator::operations::CreateContext()).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR:" << validator.getError();
        // Forward the daemon's own verdict when it gave one — a key whose policy
        // forbids this context must surface as kKeyOperationNotPermitted, which
        // the caller can act on, rather than a generic creation failure.
        return score::Result<std::uint64_t>{
            score::unexpect,
            MakeError(validator.getOperationError().value_or(CryptoErrorCode::kContextCreationFailed),
                      "CTX_CREATE daemon response invalid")};
    }

    auto ctx_id_result = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!ctx_id_result.has_value())
    {
        score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR: CTX_CREATE response has invalid context_id type";
        return score::Result<std::uint64_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "CTX_CREATE response has invalid context_id type")};
    }

    return ctx_id_result.value();
}

/// @brief Rejects a key handle that cannot drive a keyed operation context.
score::Result<std::monostate> ValidateOperationKey(const CryptoResourceId& key, std::string_view context_type)
{
    if (key.id == 0U)
    {
        score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR: " << context_type << " invalid / missing key id";
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kContextCreationFailed, "invalid / missing key id")};
    }

    if ((key.type != ResourceType::kKey) && (key.type != ResourceType::kKeySlot))
    {
        score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR: " << context_type << " invalid key type";
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "invalid key resource type")};
    }

    return std::monostate{};
}

}  // namespace

CryptoContextImpl::CryptoContextImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                                     std::shared_ptr<IBufferTranscoder> transcoder,
                                     std::optional<std::chrono::milliseconds> default_operation_timeout)
    : m_connection(std::move(connection)),
      m_transcoder(std::move(transcoder)),
      m_default_operation_timeout(default_operation_timeout)
{
}

CryptoContextImpl::~CryptoContextImpl() {}

// ---------------------------------------------------------------------------
// Context Factory — Hash
// ---------------------------------------------------------------------------

score::Result<std::unique_ptr<IHashContext>> CryptoContextImpl::CreateHashContext(const HashContextConfig& config)
{
    if (config.provider.has_value())
    {
        score::mw::log::LogError()
            << "[API][CryptoContextImpl] ERROR: Explicit provider resources are not supported for hash contexts";
        return score::Result<std::unique_ptr<IHashContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kUnsupportedOperation,
                      "Explicit provider resource selection is not supported for hash contexts")};
    }

    ContextCreationRequest request{};
    request.context_type = daemon_common::context_types::kHash;
    request.algorithm = &config.algorithm;
    request.provider_type = config.provider_type;

    const auto operation_timeout =
        ResolveOperationTimeout(config.timeout_enabled, config.operation_timeout, m_default_operation_timeout);
    auto context_id = CreateDaemonContext(m_connection, request, operation_timeout);
    if (!context_id.has_value())
    {
        return score::Result<std::unique_ptr<IHashContext>>{score::unexpect, context_id.error()};
    }

    return std::make_unique<HashContextImpl>(
        m_connection, context_id.value(), config.algorithm, m_transcoder, operation_timeout);
}

// ---------------------------------------------------------------------------
// Resource Resolution
// ---------------------------------------------------------------------------

score::Result<CryptoResourceId> CryptoContextImpl::ResolveResource(const ResourceId& resource_id, ResourceType type)
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;
    const auto operation_timeout = ResolveOperationTimeout(true, std::nullopt, m_default_operation_timeout);

    auto control_req_result = proto::ControlRequestBuilder()
                                  .forDataNodeId(m_connection->GetConnectionNodeId())
                                  .operation(score::crypto::daemon::mediator::operations::ResolveResource())
                                  .with_in_string(resource_id)
                                  .with_in_val_uint64(static_cast<std::uint64_t>(type))
                                  .build();

    if (!control_req_result.has_value())
    {
        return score::Result<CryptoResourceId>{
            score::unexpect, MakeError(CryptoErrorCode::kInternalError, "Failed to build RESOURCE_RESOLVE request")};
    }

    auto control_response_res = m_connection->SendRequest(control_req_result.value(), operation_timeout);

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation(score::crypto::daemon::mediator::operations::ResolveResource()).expectSuccess();

    if (!validator.isValid())
    {
        return score::Result<CryptoResourceId>{
            score::unexpect,
            MakeError(validator.getOperationError().value_or(CryptoErrorCode::kInternalError), validator.getError())};
    }

    auto id_result = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!id_result.has_value())
    {
        return score::Result<CryptoResourceId>{
            score::unexpect,
            MakeError(validator.getOperationError().value_or(CryptoErrorCode::kInternalError), validator.getError())};
    }

    auto type_result = validator.getParameterAt<std::uint8_t>(0, 1);
    if (!type_result.has_value())
    {
        return score::Result<CryptoResourceId>{
            score::unexpect,
            MakeError(validator.getOperationError().value_or(CryptoErrorCode::kInternalError), validator.getError())};
    }

    auto persistence_result = validator.getParameterAt<bool>(0, 2);
    if (!persistence_result.has_value())
    {
        return score::Result<CryptoResourceId>{
            score::unexpect,
            MakeError(validator.getOperationError().value_or(CryptoErrorCode::kInternalError), validator.getError())};
    }

    auto primary_provider = validator.getParameterAt<std::uint16_t>(0, 3);
    if (!primary_provider.has_value())
    {
        return score::Result<CryptoResourceId>{
            score::unexpect,
            MakeError(validator.getOperationError().value_or(CryptoErrorCode::kInternalError), validator.getError())};
    }

    CryptoResourceId resolved{};
    resolved.id = id_result.value();
    resolved.type = static_cast<ResourceType>(type_result.value());
    resolved.persistence =
        persistence_result.value() ? ResourcePersistence::kPersistent : ResourcePersistence::kEphemeral;
    resolved.primary_provider = primary_provider.value();
    return resolved;
}

// ---------------------------------------------------------------------------
// Context Factory stubs — not yet implemented
// ---------------------------------------------------------------------------

score::Result<std::unique_ptr<IMacContext>> CryptoContextImpl::CreateMacContext(const MacContextConfig& config)
{
    auto key_check = ValidateOperationKey(config.key, "CreateMacContext");
    if (!key_check.has_value())
    {
        return score::Result<std::unique_ptr<IMacContext>>{score::unexpect, key_check.error()};
    }

    ContextCreationRequest request{};
    request.context_type = daemon_common::context_types::kMac;
    request.algorithm = &config.algorithm;
    request.provider_type = config.provider_type;
    request.key_node_id = config.key.id;
    request.mode = daemon_common::ToContextMode(config.operation_mode);

    const auto operation_timeout =
        ResolveOperationTimeout(config.timeout_enabled, config.operation_timeout, m_default_operation_timeout);
    auto context_id = CreateDaemonContext(m_connection, request, operation_timeout);
    if (!context_id.has_value())
    {
        return score::Result<std::unique_ptr<IMacContext>>{score::unexpect, context_id.error()};
    }

    return std::make_unique<MacContextImpl>(
        m_connection, context_id.value(), config.algorithm, m_transcoder, operation_timeout);
}

score::Result<std::unique_ptr<IKeyManagementContext>> CryptoContextImpl::CreateKeyManagementContext(
    const KeyManagementContextConfig& config)
{
    // No algorithm: a key management context is not bound to one, and no key is
    // bound at creation either — its operations carry their own key references.
    ContextCreationRequest request{};
    request.context_type = daemon_common::context_types::kKeyManagement;
    request.provider_type = config.provider_type;

    const auto operation_timeout =
        ResolveOperationTimeout(config.timeout_enabled, config.operation_timeout, m_default_operation_timeout);
    auto context_id = CreateDaemonContext(m_connection, request, operation_timeout);
    if (!context_id.has_value())
    {
        return score::Result<std::unique_ptr<IKeyManagementContext>>{score::unexpect, context_id.error()};
    }

    return std::make_unique<KeyManagementContextImpl>(
        m_connection, context_id.value(), m_transcoder, operation_timeout);
}

// ---------------------------------------------------------------------------
// Context Factory — Cipher / Sign / Verify / Random
// ---------------------------------------------------------------------------

score::Result<std::unique_ptr<ICipherContext>> CryptoContextImpl::CreateCipherContext(const CipherContextConfig& config)
{
    auto key_check = ValidateOperationKey(config.key, "CreateCipherContext");
    if (!key_check.has_value())
    {
        return score::Result<std::unique_ptr<ICipherContext>>{score::unexpect, key_check.error()};
    }

    ContextCreationRequest request{};
    request.context_type = daemon_common::context_types::kCipher;
    request.algorithm = &config.algorithm;
    request.provider_type = config.provider_type;
    request.key_node_id = config.key.id;
    request.mode = daemon_common::ToContextMode(config.direction);
    request.padding = config.padding;

    const auto operation_timeout =
        ResolveOperationTimeout(config.timeout_enabled, config.operation_timeout, m_default_operation_timeout);
    auto context_id = CreateDaemonContext(m_connection, request, operation_timeout);
    if (!context_id.has_value())
    {
        return score::Result<std::unique_ptr<ICipherContext>>{score::unexpect, context_id.error()};
    }

    return std::make_unique<CipherContextImpl>(
        m_connection, context_id.value(), config.algorithm, m_transcoder, operation_timeout);
}

score::Result<std::unique_ptr<ISignContext>> CryptoContextImpl::CreateSignContext(const SignContextConfig& config)
{
    auto key_check = ValidateOperationKey(config.key, "CreateSignContext");
    if (!key_check.has_value())
    {
        return score::Result<std::unique_ptr<ISignContext>>{score::unexpect, key_check.error()};
    }

    ContextCreationRequest request{};
    request.context_type = daemon_common::context_types::kSign;
    request.algorithm = &config.algorithm;
    request.provider_type = config.provider_type;
    request.key_node_id = config.key.id;
    // A signing context always uses the private half of the key pair, regardless
    // of what the caller left in BaseContextConfig::operation_mode.
    request.mode = daemon_common::ToContextMode(OperationMode::kGenerate);
    request.signature_input_mode = config.input_mode;

    const auto operation_timeout =
        ResolveOperationTimeout(config.timeout_enabled, config.operation_timeout, m_default_operation_timeout);
    auto context_id = CreateDaemonContext(m_connection, request, operation_timeout);
    if (!context_id.has_value())
    {
        return score::Result<std::unique_ptr<ISignContext>>{score::unexpect, context_id.error()};
    }

    return std::make_unique<SignContextImpl>(
        m_connection, context_id.value(), config.algorithm, m_transcoder, operation_timeout);
}

score::Result<std::unique_ptr<IVerifySignatureContext>> CryptoContextImpl::CreateVerifySignatureContext(
    const VerifySignatureContextConfig& config)
{
    auto key_check = ValidateOperationKey(config.key, "CreateVerifySignatureContext");
    if (!key_check.has_value())
    {
        return score::Result<std::unique_ptr<IVerifySignatureContext>>{score::unexpect, key_check.error()};
    }

    ContextCreationRequest request{};
    request.context_type = daemon_common::context_types::kVerify;
    request.algorithm = &config.algorithm;
    request.provider_type = config.provider_type;
    request.key_node_id = config.key.id;
    // Signals the daemon to bind the public half of the key pair.
    request.mode = daemon_common::ToContextMode(OperationMode::kVerify);
    request.signature_input_mode = config.input_mode;

    const auto operation_timeout =
        ResolveOperationTimeout(config.timeout_enabled, config.operation_timeout, m_default_operation_timeout);
    auto context_id = CreateDaemonContext(m_connection, request, operation_timeout);
    if (!context_id.has_value())
    {
        return score::Result<std::unique_ptr<IVerifySignatureContext>>{score::unexpect, context_id.error()};
    }

    return std::make_unique<VerifySignatureContextImpl>(
        m_connection, context_id.value(), config.algorithm, m_transcoder, operation_timeout);
}

score::Result<std::unique_ptr<IRandomContext>> CryptoContextImpl::CreateRandomContext(const RandomContextConfig& config)
{
    // No key and no mode byte: an RNG context is keyless, so the wire call stops
    // after the provider-type slot.
    ContextCreationRequest request{};
    request.context_type = daemon_common::context_types::kRandom;
    request.algorithm = &config.algorithm;
    request.provider_type = config.provider_type;

    const auto operation_timeout =
        ResolveOperationTimeout(config.timeout_enabled, config.operation_timeout, m_default_operation_timeout);
    auto context_id = CreateDaemonContext(m_connection, request, operation_timeout);
    if (!context_id.has_value())
    {
        return score::Result<std::unique_ptr<IRandomContext>>{score::unexpect, context_id.error()};
    }

    return std::make_unique<RandomContextImpl>(
        m_connection, context_id.value(), config.algorithm, m_transcoder, operation_timeout);
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

score::Result<AlgorithmCapabilities> CryptoContextImpl::QueryCapabilities(const AlgorithmId& algorithm)
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;
    namespace med_ops = ::score::crypto::daemon::mediator::operations;

    auto control_req_result = proto::ControlRequestBuilder()
                                  .forDataNodeId(m_connection->GetConnectionNodeId())
                                  .operation(med_ops::QueryCapabilities())
                                  .with_in_string(std::string_view{algorithm})
                                  .build();
    if (!control_req_result.has_value())
    {
        return score::Result<AlgorithmCapabilities>{
            score::unexpect, MakeError(CryptoErrorCode::kInternalError, "Failed to build QUERY_CAPABILITIES request")};
    }

    auto control_response_res = m_connection->SendRequest(control_req_result.value());
    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation(med_ops::QueryCapabilities()).expectSuccess();
    if (!validator.isValid())
    {
        return score::Result<AlgorithmCapabilities>{
            score::unexpect,
            MakeError(validator.getOperationError().value_or(CryptoErrorCode::kInternalError),
                      "QUERY_CAPABILITIES daemon response invalid")};
    }

    std::size_t index = 0U;
    auto capabilities = ReadAlgorithmCapabilities(validator, index, algorithm);
    if (!capabilities.has_value())
    {
        return score::Result<AlgorithmCapabilities>{
            score::unexpect, MakeError(CryptoErrorCode::kInternalError, "QUERY_CAPABILITIES response malformed")};
    }
    return capabilities.value();
}

score::Result<SystemCapabilities> CryptoContextImpl::QueryCapabilities()
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;
    namespace med_ops = ::score::crypto::daemon::mediator::operations;

    SystemCapabilities result{};
    std::uint16_t cursor = 0U;
    std::uint16_t generation = 0U;
    std::size_t restarts = 0U;
    for (;;)
    {
        auto control_req_result = proto::ControlRequestBuilder()
                                      .forDataNodeId(m_connection->GetConnectionNodeId())
                                      .operation(med_ops::QuerySystemCapabilities())
                                      .with_in_val_uint16(cursor)
                                      .with_in_val_uint16(generation)
                                      .build();
        if (!control_req_result.has_value())
        {
            return score::Result<SystemCapabilities>{
                score::unexpect,
                MakeError(CryptoErrorCode::kInternalError, "Failed to build SYSTEM_CAPABILITIES request")};
        }

        auto control_response_res = m_connection->SendRequest(control_req_result.value());
        auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
        validator.expectOperation(med_ops::QuerySystemCapabilities()).expectSuccess();
        if (!validator.isValid())
        {
            const auto error = validator.getOperationError().value_or(CryptoErrorCode::kInternalError);
            // The providers changed since the first page: read the listing again.
            if ((error == CryptoErrorCode::kInvalidOperation) && (cursor != 0U) &&
                (restarts < kSystemCapabilitiesMaxRestarts))
            {
                ++restarts;
                result = SystemCapabilities{};
                cursor = 0U;
                generation = 0U;
                continue;
            }
            return score::Result<SystemCapabilities>{score::unexpect,
                                                     MakeError(error, "SYSTEM_CAPABILITIES daemon response invalid")};
        }

        const auto position = ReadSystemCapabilitiesPage(validator, result);
        if (!position.has_value())
        {
            return score::Result<SystemCapabilities>{
                score::unexpect,
                MakeError(position.error(),
                          (position.error() == CryptoErrorCode::kInsufficientBufferSize)
                              ? "SYSTEM_CAPABILITIES lists more providers than fit"
                              : "SYSTEM_CAPABILITIES response malformed")};
        }
        // Each page must move forward within one snapshot, or a faulty daemon could loop the client.
        const auto next = position.value().next;
        if (((next != med_ops::kSystemCapabilitiesDone) && (next <= cursor)) ||
            ((cursor != 0U) && (position.value().generation != generation)))
        {
            return score::Result<SystemCapabilities>{
                score::unexpect,
                MakeError(CryptoErrorCode::kInternalError, "SYSTEM_CAPABILITIES pages are inconsistent")};
        }
        if (next == med_ops::kSystemCapabilitiesDone)
        {
            return result;
        }
        generation = position.value().generation;
        cursor = next;
    }
}

score::Result<ProviderInfo> CryptoContextImpl::GetProviderInfo(uint16_t provider_id)
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;
    namespace med_ops = ::score::crypto::daemon::mediator::operations;

    auto control_req_result = proto::ControlRequestBuilder()
                                  .forDataNodeId(m_connection->GetConnectionNodeId())
                                  .operation(med_ops::GetProviderInfo())
                                  .with_in_val_uint64(provider_id)
                                  .build();
    if (!control_req_result.has_value())
    {
        return score::Result<ProviderInfo>{
            score::unexpect, MakeError(CryptoErrorCode::kInternalError, "Failed to build PROVIDER_INFO request")};
    }

    auto control_response_res = m_connection->SendRequest(control_req_result.value());
    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation(med_ops::GetProviderInfo()).expectSuccess();
    if (!validator.isValid())
    {
        return score::Result<ProviderInfo>{
            score::unexpect,
            MakeError(validator.getOperationError().value_or(CryptoErrorCode::kInternalError),
                      "PROVIDER_INFO daemon response invalid")};
    }

    const auto id = validator.getParameterAt<std::uint16_t>(0, 0);
    const auto type = validator.getParameterAt<std::uint8_t>(0, 1);
    const auto name = validator.getParameterAt<proto::DataBufferReturn>(0, 2);
    const auto info = (id.has_value() && type.has_value() && name.has_value())
                          ? MakeProviderInfo(id.value(), type.value(), name.value())
                          : std::nullopt;
    if (!info.has_value())
    {
        return score::Result<ProviderInfo>{
            score::unexpect, MakeError(CryptoErrorCode::kInternalError, "PROVIDER_INFO response malformed")};
    }
    return info.value();
}

score::Result<ProviderInfo> CryptoContextImpl::GetProviderInfo(const CryptoResourceId& resourceId)
{
    return GetProviderInfo(resourceId.primary_provider);
}

// ---------------------------------------------------------------------------
// Typed Object Access (TODO)
// ---------------------------------------------------------------------------

score::Result<std::unique_ptr<IKeyObject>> CryptoContextImpl::GetKeyObject(const CryptoResourceId& /*id*/)
{
    // TODO: Implement key object retrieval via daemon IPC
    return score::Result<std::unique_ptr<IKeyObject>>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "GetKeyObject not yet implemented")};
}

score::Result<std::unique_ptr<IKeySlotObject>> CryptoContextImpl::GetKeySlotObject(const CryptoResourceId& /*id*/)
{
    // TODO: Implement key slot object retrieval via daemon IPC
    return score::Result<std::unique_ptr<IKeySlotObject>>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "GetKeySlotObject not yet implemented")};
}

}  // namespace crypto

}  // namespace score
