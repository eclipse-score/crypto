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

#include "score/crypto/src/daemon/provider/provider_manager_factory.hpp"

#include <gtest/gtest.h>

namespace provider = score::crypto::daemon::provider;
namespace common = score::crypto::daemon::common;
namespace config = score::crypto::daemon::config;

TEST(ProviderManagerFactoryTest, InvalidProviderPolicyReturnsInvalidArgument)
{
    config::Config daemon_config;
    daemon_config.GetProviderConstructionPolicy().AddProvider(config::ProviderConstructionEntry{"", false});

    const auto result = provider::ProviderManagerFactory::Create(daemon_config);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kInvalidArgument);
}

TEST(ProviderManagerFactoryTest, EmptyRegistryReturnsProviderNotAvailable)
{
    config::Config daemon_config;
    daemon_config.GetProviderConstructionPolicy().AddProvider(
        config::ProviderConstructionEntry{"UNAVAILABLE_PROVIDER", false});

    const auto result = provider::ProviderManagerFactory::Create(daemon_config);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kProviderNotAvailable);
}

TEST(ProviderManagerFactoryTest, MissingRequiredProviderIsFatal)
{
    config::Config daemon_config;
    daemon_config.GetProviderConstructionPolicy().AddProvider(config::ProviderConstructionEntry{"REQUIRED_HSM", true});

    const auto result = provider::ProviderManagerFactory::Create(daemon_config);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kProviderNotAvailable);
}
