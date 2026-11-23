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

#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/mac/openssl_hmac_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/openssl_algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_handler.hpp"

#include <openssl/crypto.h>  // CRYPTO_memcmp, OPENSSL_cleanse
#include <openssl/params.h>  // OSSL_PARAM

#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include <cstring>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

using common::OperationIdentifier;
using common::StreamOperationState;
using ::score::crypto::daemon::common::DaemonErrorCode;

// ---------------------------------------------------------------------------
// Construction / destruction
// ---------------------------------------------------------------------------

OpenSslHmacHandler::OpenSslHmacHandler(std::unique_ptr<operations::mac::MacExecutor> executor,
                                       const AlgorithmDescriptor& algorithm)
    : ScoreMacHandler{std::move(executor), algorithm}
{
}

OpenSslHmacHandler::~OpenSslHmacHandler()
{
    CleanupContext();
}

void OpenSslHmacHandler::CleanupContext() noexcept
{
    if (m_ctx != nullptr)
    {
        EVP_MAC_CTX_free(m_ctx);
        m_ctx = nullptr;
    }
    if (m_mac != nullptr)
    {
        EVP_MAC_free(m_mac);
        m_mac = nullptr;
    }
    OPENSSL_cleanse(m_output_buffer.data(), m_output_buffer.size());
    m_output_buffer.clear();
}

// ---------------------------------------------------------------------------
// Static helpers
// ---------------------------------------------------------------------------

const char* OpenSslHmacHandler::GetDigestName() const noexcept
{
    if (!IsAlgorithmSupported(m_algorithm))
    {
        return nullptr;
    }
    return ::score::crypto::daemon::provider::openssl::detail::ToOpenSslDigestName(m_algorithm.hash);
}

bool OpenSslHmacHandler::IsAlgorithmSupported(const AlgorithmDescriptor& algorithm) noexcept
{
    return ::score::crypto::daemon::provider::openssl::detail::IsHmacSupported(algorithm);
}

std::size_t OpenSslHmacHandler::GetMacSize() const noexcept
{
    return IsAlgorithmSupported(m_algorithm) ? m_algorithm.output_size : 0U;
}

// ---------------------------------------------------------------------------
// Handler interface
// ---------------------------------------------------------------------------

::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslHmacHandler::InitializeContext(
    const ::score::crypto::daemon::provider::handler::InitializationParams& init_params)
{
    // Validate algorithm (m_algorithm is set at construction).
    if (!IsAlgorithmSupported(m_algorithm))
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
    }

    m_state = StreamOperationState::IDLE;

    // Fetch the EVP_MAC object for HMAC and allocate context.
    CleanupContext();
    m_mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (m_mac == nullptr)
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed);
    }
    m_ctx = EVP_MAC_CTX_new(m_mac);
    if (m_ctx == nullptr)
    {
        EVP_MAC_free(m_mac);
        m_mac = nullptr;
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed);
    }

    m_output_buffer.resize(GetMacSize());

    // Bind key if provided via InitializationParams (bound_key_handler != nullptr).
    if (init_params.bound_key_handler != nullptr)
    {
        // Provider-id check validates the key comes from the same provider (no dynamic_cast/RTTI).
        if (init_params.bound_key_handler->GetProviderId() != init_params.provider_id)
        {
            return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
        }
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast) — type tag verified above
        const auto* openssl_key = static_cast<const ::score::crypto::daemon::provider::openssl::OpenSslKeyHandler*>(
            init_params.bound_key_handler);

        std::size_t key_len{0U};
        const uint8_t* key_bytes = openssl_key->GetRawKeyBytes(key_len);
        if (key_bytes == nullptr || key_len == 0U)
        {
            return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
        }

        // Key is valid — store params so InitMac() and Reset() can use them.
        m_init_params = init_params;
        m_state = StreamOperationState::STREAM_INITIALIZED;
    }

    return std::monostate{};
}

::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode> OpenSslHmacHandler::InitMac(
    std::optional<score::cpp::span<const std::uint8_t>> iv)
{
    // HMAC takes no IV.
    if (iv.has_value())
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    if (m_ctx == nullptr)
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kStreamNotInitialized);
    }

    const auto key = ResolveKey();
    if (!key.has_value())
    {
        return ::score::crypto::make_unexpected(key.error());
    }

    // EVP_MAC_init with key + OSSL_PARAM for digest algorithm
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast) — OpenSSL OSSL_PARAM API requires non-const char*
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>(key.value().digest_name), 0),
        OSSL_PARAM_construct_end(),
    };

    const int rv = EVP_MAC_init(m_ctx, key.value().bytes, key.value().length, params);
    if (rv != 1)
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kAlgorithmInitializationFailed);
    }

    return std::monostate{};
}

::score::crypto::Expected<OpenSslHmacHandler::BoundKey, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslHmacHandler::ResolveKey() const noexcept
{
    if (m_init_params.bound_key_handler == nullptr)
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kStreamNotInitialized);
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast) — type tag verified in InitializeContext
    const auto* openssl_key = static_cast<const ::score::crypto::daemon::provider::openssl::OpenSslKeyHandler*>(
        m_init_params.bound_key_handler);
    BoundKey key{};
    key.bytes = openssl_key->GetRawKeyBytes(key.length);
    if (key.bytes == nullptr || key.length == 0U)
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kStreamNotInitialized);
    }
    key.digest_name = GetDigestName();
    if (key.digest_name == nullptr)
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
    }
    return key;
}

::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode> OpenSslHmacHandler::Reset()
{
    return InitializeContext(m_init_params);
}

// ---------------------------------------------------------------------------
// MacHandler interface
// ---------------------------------------------------------------------------

::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslHmacHandler::UpdateMac(score::cpp::span<const std::uint8_t> data)
{
    if (m_ctx == nullptr || m_state == StreamOperationState::IDLE)
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kStreamNotInitialized);
    }

    const int rv = EVP_MAC_update(m_ctx, data.data(), data.size());
    if (rv != 1)
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kAlgorithmExecutionFailed);
    }
    return std::monostate{};
}

::score::crypto::Expected<std::size_t, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslHmacHandler::FinalizeMac(score::cpp::span<std::uint8_t> tag)
{
    return FinalizeMacInternal(tag);
}

::score::crypto::Expected<std::size_t, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslHmacHandler::SingleShotMac(score::cpp::span<const std::uint8_t> data, score::cpp::span<std::uint8_t> tag)
{
    const auto key = ResolveKey();
    if (!key.has_value())
    {
        return ::score::crypto::make_unexpected(key.error());
    }

    if (tag.size() < GetMacSize())
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kInsufficientBufferSize);
    }

    // EVP_Q_mac uses its own context and does not touch m_ctx.
    std::size_t hmac_len{0U};
    const unsigned char* const out = EVP_Q_mac(nullptr,
                                               "HMAC",
                                               nullptr,
                                               key.value().digest_name,
                                               nullptr,
                                               key.value().bytes,
                                               key.value().length,
                                               data.data(),
                                               data.size(),
                                               tag.data(),
                                               tag.size(),
                                               &hmac_len);
    if (out == nullptr)
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kAlgorithmExecutionFailed);
    }
    return hmac_len;
}

::score::crypto::Expected<std::size_t, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslHmacHandler::FinalizeMacInternal(score::cpp::span<std::uint8_t> tag)
{
    if (m_ctx == nullptr)
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kStreamNotInitialized);
    }

    if (tag.size() < GetMacSize())
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kInsufficientBufferSize);
    }

    std::size_t hmac_len = 0U;
    const int rv = EVP_MAC_final(m_ctx, tag.data(), &hmac_len, tag.size());
    if (rv != 1)
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    m_state = StreamOperationState::IDLE;
    return hmac_len;
}

::score::crypto::Expected<bool, ::score::crypto::daemon::common::DaemonErrorCode> OpenSslHmacHandler::VerifyMac(
    score::cpp::span<const std::uint8_t> expected_tag)
{
    if (expected_tag.size() != GetMacSize())
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    AllocateOutputBuffer(GetMacSize());
    const auto out_len =
        FinalizeMacInternal(score::cpp::span<std::uint8_t>{m_output_buffer.data(), m_output_buffer.size()});
    if (!out_len.has_value())
    {
        OPENSSL_cleanse(m_output_buffer.data(), m_output_buffer.size());
        return ::score::crypto::make_unexpected(out_len.error());
    }

    // Constant-time comparison.
    const int match = CRYPTO_memcmp(m_output_buffer.data(), expected_tag.data(), out_len.value());
    OPENSSL_cleanse(m_output_buffer.data(), m_output_buffer.size());
    return match == 0;
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

void OpenSslHmacHandler::AllocateOutputBuffer(std::size_t size)
{
    m_output_buffer.clear();
    m_output_buffer.resize(size);
}

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler
