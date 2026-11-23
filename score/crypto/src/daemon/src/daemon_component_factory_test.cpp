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

#include "score/crypto/src/daemon/src/daemon_component_factory.hpp"

#include <gtest/gtest.h>

#include <memory>

namespace score::crypto::daemon
{
namespace
{

class NullHandlerChainFactory final : public control_plane::IHandlerChainFactory
{
  public:
    std::unique_ptr<control_plane::IRequestHandler> CreateRequestHandler() override
    {
        return nullptr;
    }
};

TEST(DaemonComponentFactoryTest, CreateControlServerPassesCreationErrorThrough)
{
    DaemonComponentFactory factory;

    const auto result = factory.CreateControlServer(nullptr, config::IPCConfig{}, {}, {});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kInvalidArgument);
}

TEST(DaemonComponentFactoryTest, CreateControlServerReturnsServer)
{
    DaemonComponentFactory factory;

    auto result = factory.CreateControlServer(std::make_unique<NullHandlerChainFactory>(), config::IPCConfig{}, {}, {});

    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result.value(), nullptr);
}

}  // namespace
}  // namespace score::crypto::daemon
