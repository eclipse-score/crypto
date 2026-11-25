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

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <memory>
#include <variant>
#include <vector>

#include "score/crypto/src/api/types/key.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_handler.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_types.hpp"
#include "score/crypto/src/daemon/provider/handler/handler_init_params.hpp"
#include "score/crypto/src/daemon/provider/handler/i_crypto_handler_factory.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/mac_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/i_provider.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/provider_openssl.hpp"

namespace common = score::crypto::daemon::common;
namespace key_management = score::crypto::daemon::key_management;
namespace provider = score::crypto::daemon::provider;
namespace handler = score::crypto::daemon::provider::handler;
namespace mac_ops = handler::mac_handler_operations;

namespace
{

using Bytes = std::vector<std::uint8_t>;
using ExecuteResult = score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode>;

constexpr std::size_t kTagSize = 32U;

// Bytes 0x01..0x20, imported as an HMAC-SHA256 key.
constexpr std::array<std::uint8_t, 32U> kKey = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                                0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                                                0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

// HMAC-SHA256(kKey, "abc").
const Bytes kTagAbc = {0xa2, 0x1b, 0x1f, 0x5d, 0x4c, 0xf4, 0xf7, 0x3a, 0x4d, 0xd9, 0x39, 0x75, 0x0f, 0x7a, 0x06, 0x6a,
                       0x7f, 0x98, 0xcc, 0x13, 0x1c, 0xb1, 0x6a, 0x66, 0x92, 0x75, 0x90, 0x21, 0xcf, 0xab, 0x81, 0x81};

// HMAC-SHA256(kKey, "").
const Bytes kTagEmpty = {0x46, 0x24, 0x76, 0xa8, 0x97, 0xdd, 0xfd, 0xbd, 0x40, 0xd1, 0x42,
                         0x0e, 0x08, 0xa5, 0xbc, 0xfe, 0xeb, 0x25, 0xc3, 0xe2, 0xad, 0xe6,
                         0xa0, 0xa9, 0x08, 0x3b, 0x32, 0x7b, 0x9e, 0xf9, 0xfc, 0xa1};

const Bytes kAbc = {'a', 'b', 'c'};

score::cpp::span<const std::uint8_t> In(const std::uint8_t* data, std::size_t size)
{
    return score::cpp::span<const std::uint8_t>{data, size};
}

score::cpp::span<const std::uint8_t> In(const Bytes& buffer)
{
    return In(buffer.data(), buffer.size());
}

score::cpp::span<std::uint8_t> Out(Bytes& buffer)
{
    return score::cpp::span<std::uint8_t>{buffer.data(), buffer.size()};
}

/// Asserts a one-element uint64_t response and returns its value.
void ExpectSize(const ExecuteResult& result, std::uint64_t expected)
{
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result.value().size(), 1U);
    const auto* value = std::get_if<std::uint64_t>(&result.value().front());
    ASSERT_NE(value, nullptr);
    EXPECT_EQ(*value, expected);
}

void ExpectVerdict(const ExecuteResult& result, bool expected)
{
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result.value().size(), 1U);
    const auto* value = std::get_if<bool>(&result.value().front());
    ASSERT_NE(value, nullptr);
    EXPECT_EQ(*value, expected);
}

void ExpectError(const ExecuteResult& result, common::DaemonErrorCode expected)
{
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), expected);
}

class ProviderMacTest : public ::testing::Test
{
  protected:
    static void SetUpTestSuite()
    {
        provider_ = std::make_shared<provider::score_provider::openssl::OpenSSL>();
        ASSERT_TRUE(provider_->Initialize(provider::ProviderInitContext{0, "OPENSSL"}));
        auto key_factory = provider_->GetKeyFactory();
        ASSERT_NE(key_factory, nullptr);

        key_management::KeyImportRequest request{};
        request.key_data = kKey.data();
        request.key_data_size = kKey.size();
        request.algorithm = Algorithm();
        request.permissions = score::crypto::KeyOperationPermission::kMac;
        auto imported = key_factory->ImportKey(request);
        ASSERT_TRUE(imported.has_value());
        key_ = std::move(imported.value());
    }

    static void TearDownTestSuite()
    {
        if (key_ != nullptr)
        {
            static_cast<void>(key_->Release());
            key_.reset();
        }
        if (provider_ != nullptr)
        {
            provider_->Shutdown();
            provider_.reset();
        }
    }

    void SetUp() override
    {
        mac_ = CreateHandler();
        ASSERT_NE(mac_, nullptr);
        ASSERT_TRUE(mac_->InitializeContext(BoundKeyParams()).has_value());
    }

    static score::crypto::AlgorithmDescriptor Algorithm()
    {
        return score::crypto::GetAlgorithmDescriptor("HMAC-SHA256").value();
    }

    static handler::Handler::Sptr CreateHandler()
    {
        auto factory = provider_->GetCryptoHandlerFactory();
        EXPECT_NE(factory, nullptr);
        auto created = factory->CreateHandler("MAC", Algorithm());
        EXPECT_TRUE(created.has_value());
        return created.has_value() ? created.value() : nullptr;
    }

    static handler::InitializationParams BoundKeyParams()
    {
        handler::InitializationParams params;
        params.provider_id = provider_->GetProviderId();
        params.context_node_id = 1U;
        params.key_node_id = 1U;
        params.bound_key_handler = key_.get();
        return params;
    }

    static ExecuteResult Execute(handler::Handler& mac,
                                 common::OperationAction action,
                                 common::RequestParameters request = {})
    {
        return mac.Execute({common::actors::OP_ACTOR_MAC_HANDLER, action}, request);
    }

    ExecuteResult Execute(common::OperationAction action, common::RequestParameters request = {})
    {
        return Execute(*mac_, action, std::move(request));
    }

    /// Runs INIT, UPDATE("abc") and FINALIZE on @p mac and expects the known tag.
    static void ExpectStreamProducesKnownTag(handler::Handler& mac)
    {
        ASSERT_TRUE(Execute(mac, mac_ops::MAC_INIT).has_value());
        ASSERT_TRUE(Execute(mac, mac_ops::MAC_UPDATE, {In(kAbc)}).has_value());
        Bytes tag(kTagSize);
        ExpectSize(Execute(mac, mac_ops::MAC_FINALIZE, {Out(tag)}), kTagSize);
        EXPECT_EQ(tag, kTagAbc);
    }

    static std::shared_ptr<provider::IProvider> provider_;
    static key_management::IKeyHandler::Sptr key_;
    handler::Handler::Sptr mac_;
};

std::shared_ptr<provider::IProvider> ProviderMacTest::provider_;
key_management::IKeyHandler::Sptr ProviderMacTest::key_;

TEST_F(ProviderMacTest, SingleShotProducesKnownTag)
{
    Bytes tag(kTagSize);
    ExpectSize(Execute(mac_ops::MAC_SS, {In(kAbc), Out(tag)}), kTagSize);
    EXPECT_EQ(tag, kTagAbc);
}

TEST_F(ProviderMacTest, SingleShotOverEmptyMessageProducesKnownTag)
{
    Bytes tag(kTagSize);
    ExpectSize(Execute(mac_ops::MAC_SS, {In(nullptr, 0U), Out(tag)}), kTagSize);
    EXPECT_EQ(tag, kTagEmpty);
}

TEST_F(ProviderMacTest, StreamingAcrossChunksProducesKnownTag)
{
    ASSERT_TRUE(Execute(mac_ops::MAC_INIT).has_value());
    ASSERT_TRUE(Execute(mac_ops::MAC_UPDATE, {In(kAbc.data(), 1U)}).has_value());
    ASSERT_TRUE(Execute(mac_ops::MAC_UPDATE, {In(kAbc.data() + 1U, 2U)}).has_value());

    Bytes tag(kTagSize);
    ExpectSize(Execute(mac_ops::MAC_FINALIZE, {Out(tag)}), kTagSize);
    EXPECT_EQ(tag, kTagAbc);
}

TEST_F(ProviderMacTest, FinalizeIncludesTrailingChunk)
{
    ASSERT_TRUE(Execute(mac_ops::MAC_INIT).has_value());
    ASSERT_TRUE(Execute(mac_ops::MAC_UPDATE, {In(kAbc.data(), 1U)}).has_value());

    Bytes tag(kTagSize);
    ExpectSize(Execute(mac_ops::MAC_FINALIZE, {Out(tag), In(kAbc.data() + 1U, 2U)}), kTagSize);
    EXPECT_EQ(tag, kTagAbc);
}

TEST_F(ProviderMacTest, FinalizeRejectsShortTagBeforeTrailingChunkSoRetrySucceeds)
{
    ASSERT_TRUE(Execute(mac_ops::MAC_INIT).has_value());
    ASSERT_TRUE(Execute(mac_ops::MAC_UPDATE, {In(kAbc.data(), 1U)}).has_value());

    Bytes short_tag(kTagSize - 1U);
    ExpectError(Execute(mac_ops::MAC_FINALIZE, {Out(short_tag), In(kAbc.data() + 1U, 2U)}),
                common::DaemonErrorCode::kInsufficientBufferSize);

    Bytes tag(kTagSize);
    ExpectSize(Execute(mac_ops::MAC_FINALIZE, {Out(tag), In(kAbc.data() + 1U, 2U)}), kTagSize);
    EXPECT_EQ(tag, kTagAbc);
}

TEST_F(ProviderMacTest, FinalizeRejectsShortTagAndKeepsStream)
{
    ASSERT_TRUE(Execute(mac_ops::MAC_INIT).has_value());
    ASSERT_TRUE(Execute(mac_ops::MAC_UPDATE, {In(kAbc)}).has_value());

    Bytes short_tag(kTagSize - 1U);
    ExpectError(Execute(mac_ops::MAC_FINALIZE, {Out(short_tag)}), common::DaemonErrorCode::kInsufficientBufferSize);

    Bytes tag(kTagSize);
    ExpectSize(Execute(mac_ops::MAC_FINALIZE, {Out(tag)}), kTagSize);
    EXPECT_EQ(tag, kTagAbc);
}

TEST_F(ProviderMacTest, VerifyAcceptsMatchingTagAndRejectsTamperedTag)
{
    ASSERT_TRUE(Execute(mac_ops::MAC_INIT).has_value());
    ASSERT_TRUE(Execute(mac_ops::MAC_UPDATE, {In(kAbc)}).has_value());
    ExpectVerdict(Execute(mac_ops::MAC_VERIFY, {In(kTagAbc)}), true);

    auto tampered = kTagAbc;
    tampered[0U] ^= 0x01U;
    ASSERT_TRUE(Execute(mac_ops::MAC_INIT).has_value());
    ASSERT_TRUE(Execute(mac_ops::MAC_UPDATE, {In(kAbc)}).has_value());
    ExpectVerdict(Execute(mac_ops::MAC_VERIFY, {In(tampered)}), false);
}

TEST_F(ProviderMacTest, VerifyRejectsWrongLengthTagAndKeepsStream)
{
    ASSERT_TRUE(Execute(mac_ops::MAC_INIT).has_value());
    ASSERT_TRUE(Execute(mac_ops::MAC_UPDATE, {In(kAbc)}).has_value());

    const Bytes short_tag(kTagAbc.begin(), kTagAbc.end() - 1);
    Bytes long_tag = kTagAbc;
    long_tag.push_back(0x00U);
    ExpectError(Execute(mac_ops::MAC_VERIFY, {In(short_tag)}), common::DaemonErrorCode::kInvalidArgument);
    ExpectError(Execute(mac_ops::MAC_VERIFY, {In(long_tag)}), common::DaemonErrorCode::kInvalidArgument);

    ExpectVerdict(Execute(mac_ops::MAC_VERIFY, {In(kTagAbc)}), true);
}

TEST_F(ProviderMacTest, GetSizeReportsTagLength)
{
    ExpectSize(Execute(mac_ops::MAC_GET_SIZE), kTagSize);
}

TEST_F(ProviderMacTest, SingleShotRejectsMalformedRequests)
{
    Bytes tag(kTagSize);
    Bytes short_tag(kTagSize - 1U);

    ExpectError(Execute(mac_ops::MAC_SS, {In(kAbc)}), common::DaemonErrorCode::kInsufficientParameters);
    ExpectError(Execute(mac_ops::MAC_SS, {In(kAbc), In(tag)}), common::DaemonErrorCode::kInvalidDataType);
    ExpectError(Execute(mac_ops::MAC_SS, {In(kAbc), Out(short_tag)}), common::DaemonErrorCode::kInsufficientBufferSize);
}

TEST_F(ProviderMacTest, RejectsMalformedStreamingRequestsAndKeepsStream)
{
    Bytes tag(kTagSize);
    const std::uint64_t scalar{1U};

    ExpectError(Execute(mac_ops::MAC_INIT, {In(kAbc), In(kAbc)}), common::DaemonErrorCode::kInvalidArgument);
    ExpectError(Execute(mac_ops::MAC_INIT, {scalar}), common::DaemonErrorCode::kInvalidDataType);
    ASSERT_TRUE(Execute(mac_ops::MAC_INIT).has_value());

    ExpectError(Execute(mac_ops::MAC_UPDATE, {In(kAbc), In(kAbc)}), common::DaemonErrorCode::kInvalidArgument);
    ExpectError(Execute(mac_ops::MAC_UPDATE, {scalar}), common::DaemonErrorCode::kInvalidDataType);
    ASSERT_TRUE(Execute(mac_ops::MAC_UPDATE, {In(kAbc)}).has_value());

    ExpectError(Execute(mac_ops::MAC_FINALIZE, {}), common::DaemonErrorCode::kInsufficientParameters);
    ExpectError(Execute(mac_ops::MAC_FINALIZE, {Out(tag), In(kAbc), In(kAbc)}),
                common::DaemonErrorCode::kInvalidArgument);
    ExpectError(Execute(mac_ops::MAC_FINALIZE, {In(tag)}), common::DaemonErrorCode::kInvalidDataType);
    ExpectError(Execute(mac_ops::MAC_FINALIZE, {Out(tag), scalar}), common::DaemonErrorCode::kInvalidDataType);

    ExpectError(Execute(mac_ops::MAC_VERIFY, {}), common::DaemonErrorCode::kInsufficientParameters);
    ExpectError(Execute(mac_ops::MAC_VERIFY, {scalar}), common::DaemonErrorCode::kInvalidDataType);

    ExpectSize(Execute(mac_ops::MAC_FINALIZE, {Out(tag)}), kTagSize);
    EXPECT_EQ(tag, kTagAbc);
}

TEST_F(ProviderMacTest, SingleShotIsRejectedWhileStreamIsActive)
{
    ASSERT_TRUE(Execute(mac_ops::MAC_INIT).has_value());
    ASSERT_TRUE(Execute(mac_ops::MAC_UPDATE, {In(kAbc)}).has_value());

    Bytes tag(kTagSize);
    ExpectError(Execute(mac_ops::MAC_SS, {In(kAbc), Out(tag)}), common::DaemonErrorCode::kOperationInProgress);
}

TEST_F(ProviderMacTest, SingleShotAfterInitEndsTheStream)
{
    ASSERT_TRUE(Execute(mac_ops::MAC_INIT).has_value());

    Bytes tag(kTagSize);
    ExpectSize(Execute(mac_ops::MAC_SS, {In(kAbc), Out(tag)}), kTagSize);
    EXPECT_EQ(tag, kTagAbc);

    ExpectError(Execute(mac_ops::MAC_UPDATE, {In(kAbc)}), common::DaemonErrorCode::kInvalidStreamOperation);
}

TEST_F(ProviderMacTest, SingleShotThenStreamingOnSameHandler)
{
    Bytes first(kTagSize);
    ExpectSize(Execute(mac_ops::MAC_SS, {In(kAbc), Out(first)}), kTagSize);
    EXPECT_EQ(first, kTagAbc);

    Bytes second(kTagSize);
    ExpectSize(Execute(mac_ops::MAC_SS, {In(kAbc), Out(second)}), kTagSize);
    EXPECT_EQ(second, kTagAbc);

    ExpectStreamProducesKnownTag(*mac_);
}

TEST_F(ProviderMacTest, SingleShotWithoutBoundKeyIsRejected)
{
    auto unbound = CreateHandler();
    ASSERT_NE(unbound, nullptr);
    handler::InitializationParams params;
    params.provider_id = provider_->GetProviderId();
    ASSERT_TRUE(unbound->InitializeContext(params).has_value());

    Bytes tag(kTagSize);
    ExpectError(Execute(*unbound, mac_ops::MAC_SS, {In(kAbc), Out(tag)}),
                common::DaemonErrorCode::kStreamNotInitialized);
}

TEST_F(ProviderMacTest, HmacInitRejectsIv)
{
    const Bytes iv(16U, 0x00U);
    ExpectError(Execute(mac_ops::MAC_INIT, {In(iv)}), common::DaemonErrorCode::kInvalidArgument);
}

}  // namespace
