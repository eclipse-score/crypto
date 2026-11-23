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

#include "score/crypto/src/daemon/src/disconnect_cleanup_callback.hpp"

#include "score/crypto/src/daemon/data_manager/data_manager.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"
#include "score/crypto/src/daemon/data_manager/data_node_accessor.hpp"

#include <gtest/gtest.h>

#include <memory>

namespace score::crypto::daemon::detail
{
namespace
{

constexpr common::ClientId kDisconnectedClient{7U};
constexpr common::ClientId kOtherClient{8U};

TEST(DisconnectCleanupCallbackTest, DeletesOnlyTheDisconnectedClientsNodes)
{
    auto data_manager = std::make_shared<data_manager::DataManager>();
    const auto disconnected_node =
        data_manager->addNode(kDisconnectedClient, std::make_shared<data_manager::DataNode>(false));
    const auto other_node = data_manager->addNode(kOtherClient, std::make_shared<data_manager::DataNode>(false));
    ASSERT_TRUE(disconnected_node.has_value());
    ASSERT_TRUE(other_node.has_value());

    const auto cleanup = MakeDisconnectCleanupCallback(data_manager, nullptr);

    EXPECT_TRUE(cleanup(kDisconnectedClient).has_value());
    EXPECT_FALSE(data_manager->getNodeAccessor(kDisconnectedClient, disconnected_node.value()).has_value());
    EXPECT_TRUE(data_manager->getNodeAccessor(kOtherClient, other_node.value()).has_value());
}

TEST(DisconnectCleanupCallbackTest, SucceedsForClientWithoutNodes)
{
    const auto cleanup = MakeDisconnectCleanupCallback(std::make_shared<data_manager::DataManager>(), nullptr);

    EXPECT_TRUE(cleanup(kDisconnectedClient).has_value());
}

TEST(DisconnectCleanupCallbackTest, SucceedsWithoutServices)
{
    const auto cleanup = MakeDisconnectCleanupCallback(nullptr, nullptr);

    EXPECT_TRUE(cleanup(kDisconnectedClient).has_value());
}

}  // namespace
}  // namespace score::crypto::daemon::detail
