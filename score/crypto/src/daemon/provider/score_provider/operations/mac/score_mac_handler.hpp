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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_MAC_SCORE_MAC_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_MAC_SCORE_MAC_HANDLER_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/handler/i_handler.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>

namespace score::crypto::daemon::provider::score_provider::operations::mac
{

class MacExecutor;

/// @brief Abstract base handler for MAC operations under the score interface family.
///
/// Implements the daemon's Handler interface by delegating Execute() to the
/// injected MacExecutor. Concrete score-interface providers (e.g. OpenSSL)
/// inherit from this class and override the typed MAC methods.
///
/// Typed methods default to kUnsupportedOperation so that a partially-implemented
/// provider compiles and returns a clear error at runtime.
///
/// Key binding is performed via InitializeContext(): the mediator sets
/// bound_key_handler before calling InitializeContext(), which the concrete
/// handler uses to bind the key.
class ScoreMacHandler : public handler::Handler
{
  public:
    using Sptr = std::shared_ptr<ScoreMacHandler>;

    ScoreMacHandler() = delete;

    /// @param executor   MAC executor injected by the handler factory.
    /// @param algorithm  Algorithm identifier (e.g. "HMAC-SHA256").
    explicit ScoreMacHandler(std::unique_ptr<MacExecutor> executor, const AlgorithmDescriptor& algorithm);

    ~ScoreMacHandler() override = default;

    // -----------------------------------------------------------------------
    // Handler interface
    // -----------------------------------------------------------------------

    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        const common::OperationIdentifier& operationId,
        common::RequestParameters& request) override;

    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const handler::InitializationParams& init_params) override;

    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> Reset() override;

    // -----------------------------------------------------------------------
    // Stream state management
    // -----------------------------------------------------------------------

    [[nodiscard]] common::StreamOperationState GetOperationState() const noexcept
    {
        return m_state;
    }

    void SetOperationState(common::StreamOperationState state) noexcept
    {
        m_state = state;
    }

    [[nodiscard]] const AlgorithmDescriptor& GetAlgorithm() const noexcept
    {
        return m_algorithm;
    }

    // -----------------------------------------------------------------------
    // Typed MAC operations — override in concrete provider handlers
    // -----------------------------------------------------------------------

    /// @brief Get the MAC tag size for the current algorithm.
    [[nodiscard]] virtual std::size_t GetMacSize() const noexcept;

    /// @brief Initialize the MAC stream context with the bound key.
    /// @param iv Absent for MAC algorithms that take no IV.
    [[nodiscard]] virtual Expected<std::monostate, common::DaemonErrorCode> InitMac(
        std::optional<score::cpp::span<const std::uint8_t>> iv);

    /// @brief Add a data chunk to the active MAC stream.
    [[nodiscard]] virtual Expected<std::monostate, common::DaemonErrorCode> UpdateMac(
        score::cpp::span<const std::uint8_t> data);

    /// @brief Finish the stream and write the tag into the caller's buffer.
    /// @return Bytes written.
    [[nodiscard]] virtual Expected<std::size_t, common::DaemonErrorCode> FinalizeMac(
        score::cpp::span<std::uint8_t> tag);

    /// @brief Finish the stream and compare its tag with @p expected_tag in constant time.
    /// @return false on a mismatch, which is not an error.
    [[nodiscard]] virtual Expected<bool, common::DaemonErrorCode> VerifyMac(
        score::cpp::span<const std::uint8_t> expected_tag);

    /// @brief Compute the tag over @p data in one call, without a streaming sequence.
    /// @return Bytes written.
    [[nodiscard]] virtual Expected<std::size_t, common::DaemonErrorCode> SingleShotMac(
        score::cpp::span<const std::uint8_t> data,
        score::cpp::span<std::uint8_t> tag);

  protected:
    AlgorithmDescriptor m_algorithm;
    common::StreamOperationState m_state{common::StreamOperationState::IDLE};

  private:
    std::unique_ptr<MacExecutor> m_executor;
};

}  // namespace score::crypto::daemon::provider::score_provider::operations::mac

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_MAC_SCORE_MAC_HANDLER_HPP
