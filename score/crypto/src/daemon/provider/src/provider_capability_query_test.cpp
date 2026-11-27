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

// Unit tests for the provider queries and their registrar, without a mediator.
// The answers themselves are covered through the mediator in mediator_capabilities_test.

#include "score/crypto/src/daemon/provider/provider_capability_query.hpp"
#include "score/crypto/src/daemon/provider/provider_query_registrar.hpp"

#include "score/crypto/common/error_domain.hpp"
#include "score/crypto/src/daemon/common/context/i_mediator_registrar.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <utility>

namespace score::crypto::daemon::provider
{
namespace
{

namespace protocol = control_plane::protocol;
namespace mediator_ops = mediator::operations;

constexpr auto kInvalidArgument =
    static_cast<protocol::OperationResult>(score::crypto::CryptoErrorCode::kInvalidArgument);

/// Builds a one-operation request, hands it to @p query and returns the operation's response.
template <typename BuildOperation>
protocol::SingleOperationResponse RunQuery(common::IMediatorQuery& query, BuildOperation&& build_operation)
{
    protocol::ControlRequestBuilder builder;
    builder.forDataNodeId(1U);
    build_operation(builder);
    auto request = builder.build();
    EXPECT_TRUE(request.has_value());
    EXPECT_EQ(request.value().operations.size(), 1U);

    protocol::OperationResponseBuilder response_builder;
    (void)query.Handle(request.value(), request.value().operations.front(), response_builder);
    const auto response = response_builder.build();
    EXPECT_TRUE(response.has_value());
    EXPECT_EQ(response.value().size(), 1U);
    return response.value().front();
}

class RegistriesFixture
{
  protected:
    common::ContextFactoryRegistry m_context_factories;
    common::ResourceResolverRegistry m_resource_resolvers;
    common::MediatorQueryRegistry m_mediator_queries;
    common::MediatorRegistries m_registries{m_context_factories, m_resource_resolvers, m_mediator_queries};
};

class ProviderQueryRegistrarTest : public ::testing::Test, protected RegistriesFixture
{
};

TEST_F(ProviderQueryRegistrarTest, RegistersOneQueryPerOperationCodeAndNothingElse)
{
    const ProviderQueryRegistrar registrar{nullptr};
    ASSERT_TRUE(registrar.Register(m_registries));

    EXPECT_NE(std::dynamic_pointer_cast<ProviderInfoQuery>(m_mediator_queries.Find(mediator_ops::PROVIDER_INFO)),
              nullptr);
    EXPECT_NE(std::dynamic_pointer_cast<AlgorithmCapabilitiesQuery>(
                  m_mediator_queries.Find(mediator_ops::QUERY_CAPABILITIES)),
              nullptr);
    EXPECT_NE(
        std::dynamic_pointer_cast<SystemCapabilitiesQuery>(m_mediator_queries.Find(mediator_ops::SYSTEM_CAPABILITIES)),
        nullptr);
    for (const auto action : mediator_ops::kBuiltInActions)
    {
        EXPECT_EQ(m_mediator_queries.Find(action), nullptr) << action;
    }
    EXPECT_EQ(m_context_factories.Find(std::string{"HASH"}), nullptr);
    EXPECT_EQ(m_resource_resolvers.Find(score::crypto::ResourceType::kKeySlot), nullptr);
}

TEST_F(ProviderQueryRegistrarTest, FailsWhenAnOperationCodeIsAlreadyTaken)
{
    ASSERT_TRUE(m_mediator_queries.Register(mediator_ops::QUERY_CAPABILITIES,
                                            std::make_shared<SystemCapabilitiesQuery>(nullptr)));

    const ProviderQueryRegistrar registrar{nullptr};
    EXPECT_FALSE(registrar.Register(m_registries));
}

TEST(ProviderQueryTest, WithoutSnapshotReportsNoProviderAndRejectsProviderInfo)
{
    ProviderInfoQuery info_query{nullptr};
    const auto info = RunQuery(info_query, [](auto& b) {
        b.operation(mediator_ops::GetProviderInfo()).with_in_val_uint64(0U);
    });
    EXPECT_EQ(info.result, kInvalidArgument);

    AlgorithmCapabilitiesQuery caps_query{nullptr};
    const auto caps = RunQuery(caps_query, [](auto& b) {
        b.operation(mediator_ops::QueryCapabilities()).with_in_string("SHA-256");
    });
    ASSERT_EQ(caps.result, protocol::OPERATION_RESULT_SUCCESS);
    ASSERT_EQ(caps.parameters.size(), 1U);
    EXPECT_EQ(std::get<std::uint16_t>(caps.parameters[0]), 0U);

    SystemCapabilitiesQuery system_query{nullptr};
    const auto system = RunQuery(system_query, [](auto& b) {
        b.operation(mediator_ops::QuerySystemCapabilities()).with_in_val_uint16(0U).with_in_val_uint16(0U);
    });
    ASSERT_EQ(system.result, protocol::OPERATION_RESULT_SUCCESS);
    ASSERT_EQ(system.parameters.size(), 4U);
    EXPECT_EQ(std::get<std::uint16_t>(system.parameters[0]), mediator_ops::kSystemCapabilitiesDone);
    EXPECT_EQ(std::get<std::uint16_t>(system.parameters[2]), 0U);
    EXPECT_EQ(std::get<std::uint16_t>(system.parameters[3]), 0U);
}

TEST(ProviderQueryTest, WithEmptyProviderManagerReportsNoProvider)
{
    auto manager = std::make_shared<ProviderManager>(config::Config{}.GetProviderInitConfig());
    (void)manager->Initialize();
    SystemCapabilitiesQuery query{std::make_shared<const ProviderCapabilitySnapshot>(manager)};

    const auto system = RunQuery(query, [](auto& b) {
        b.operation(mediator_ops::QuerySystemCapabilities()).with_in_val_uint16(0U).with_in_val_uint16(0U);
    });
    ASSERT_EQ(system.result, protocol::OPERATION_RESULT_SUCCESS);
    ASSERT_EQ(system.parameters.size(), 4U);
    EXPECT_EQ(std::get<std::uint16_t>(system.parameters[0]), mediator_ops::kSystemCapabilitiesDone);
    EXPECT_EQ(std::get<std::uint16_t>(system.parameters[2]), 0U);
}

}  // namespace
}  // namespace score::crypto::daemon::provider
