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

#include "score/crypto/src/daemon/src/crypto_daemon.hpp"

#include "score/mw/lifecycle/applicationcontext.h"

#include <score/stop_token.hpp>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <chrono>
#include <cstdlib>
#include <future>
#include <memory>
#include <utility>
#include <variant>

namespace score::crypto::daemon
{
namespace
{

using ::testing::_;
using ::testing::InSequence;
using ::testing::NiceMock;
using ::testing::Return;

using StartResult = score::crypto::Expected<std::monostate, common::DaemonErrorCode>;

class MockControlServer : public control_plane::IControlServer
{
  public:
    MOCK_METHOD(StartResult, Start, (), (override));
    MOCK_METHOD(void, WaitForTermination, (), (override));
    MOCK_METHOD(void, Stop, (), (override));
};

class MockDaemonComponentFactory : public IDaemonComponentFactory
{
  public:
    MOCK_METHOD(bool, ParseConfig, (config::Config&), (override));
    MOCK_METHOD(ProviderManagerResult, CreateProviderManager, (config::Config&), (override));
    MOCK_METHOD(ControlServerResult,
                CreateControlServer,
                (std::unique_ptr<control_plane::IHandlerChainFactory>,
                 const config::IPCConfig&,
                 ipc::message_passing::AuthorizationCallback,
                 ipc::message_passing::DisconnectCleanupCallback),
                (override));
};

class CryptoDaemonTest : public ::testing::Test
{
  protected:
    CryptoDaemonTest()
    {
        auto factory = std::make_unique<NiceMock<MockDaemonComponentFactory>>();
        m_factory = factory.get();
        m_daemon = std::make_unique<CryptoDaemon>(std::move(factory));

        ON_CALL(*m_factory, ParseConfig(_)).WillByDefault(Return(true));
        ON_CALL(*m_factory, CreateProviderManager(_)).WillByDefault([](config::Config&) {
            return IDaemonComponentFactory::ProviderManagerResult{
                std::make_shared<provider::ProviderManager>(config::ProviderInitConfig{})};
        });
    }

    /// Makes the factory return a mock server whose Start() succeeds.
    /// Returns the mock so the test can set expectations.
    MockControlServer& ProvideServer()
    {
        auto server = std::make_unique<MockControlServer>();
        MockControlServer& server_ref = *server;
        ON_CALL(server_ref, Start()).WillByDefault(Return(StartResult{std::monostate{}}));
        EXPECT_CALL(*m_factory, CreateControlServer(_, _, _, _))
            .WillOnce([server = std::move(server)](auto&&...) mutable {
                return IDaemonComponentFactory::ControlServerResult{
                    std::unique_ptr<control_plane::IControlServer>{std::move(server)}};
            });
        return server_ref;
    }

    std::int32_t Initialize()
    {
        const char* argv[] = {"crypto_daemon"};
        const score::mw::lifecycle::ApplicationContext context{1, argv};
        return m_daemon->Initialize(context);
    }

    /// Calls Run() with a token that is already stopped, so a daemon with a running server returns at once.
    std::int32_t RunWithStoppedToken()
    {
        score::cpp::stop_source stop_source;
        stop_source.request_stop();
        return m_daemon->Run(stop_source.get_token());
    }

    MockDaemonComponentFactory* m_factory{nullptr};
    std::unique_ptr<CryptoDaemon> m_daemon;
};

TEST_F(CryptoDaemonTest, InitializeFailsWhenConfigurationCannotBeParsed)
{
    EXPECT_CALL(*m_factory, ParseConfig(_)).WillOnce(Return(false));
    EXPECT_CALL(*m_factory, CreateProviderManager(_)).Times(0);
    EXPECT_CALL(*m_factory, CreateControlServer(_, _, _, _)).Times(0);

    EXPECT_NE(Initialize(), EXIT_SUCCESS);
    EXPECT_EQ(RunWithStoppedToken(), EXIT_FAILURE);
}

TEST_F(CryptoDaemonTest, InitializeFailsWhenProviderManagerCannotBeCreated)
{
    EXPECT_CALL(*m_factory, CreateProviderManager(_))
        .WillOnce(Return(score::crypto::make_unexpected(common::DaemonErrorCode::kInternalError)));
    EXPECT_CALL(*m_factory, CreateControlServer(_, _, _, _)).Times(0);

    EXPECT_NE(Initialize(), EXIT_SUCCESS);
    EXPECT_EQ(RunWithStoppedToken(), EXIT_FAILURE);
}

TEST_F(CryptoDaemonTest, InitializeFailsWhenControlServerCannotBeCreated)
{
    EXPECT_CALL(*m_factory, CreateControlServer(_, _, _, _)).WillOnce([](auto&&...) {
        return IDaemonComponentFactory::ControlServerResult{
            score::crypto::make_unexpected(common::DaemonErrorCode::kInternalError)};
    });

    EXPECT_NE(Initialize(), EXIT_SUCCESS);
    EXPECT_EQ(RunWithStoppedToken(), EXIT_FAILURE);
}

TEST_F(CryptoDaemonTest, InitializeFailsAndLeavesNoServerWhenStartFails)
{
    MockControlServer& server = ProvideServer();
    EXPECT_CALL(server, Start())
        .WillOnce(Return(StartResult{score::crypto::make_unexpected(common::DaemonErrorCode::kConnectionFailed)}));

    EXPECT_NE(Initialize(), EXIT_SUCCESS);
    EXPECT_EQ(RunWithStoppedToken(), EXIT_FAILURE);
}

TEST_F(CryptoDaemonTest, InitializeStartsServerWithAuthorizationAndCleanupCallbacks)
{
    ipc::message_passing::AuthorizationCallback authorization;
    ipc::message_passing::DisconnectCleanupCallback cleanup;
    auto server = std::make_unique<NiceMock<MockControlServer>>();
    EXPECT_CALL(*server, Start()).WillOnce(Return(StartResult{std::monostate{}}));
    EXPECT_CALL(*m_factory, CreateControlServer(_, _, _, _))
        .WillOnce([&authorization, &cleanup, server = std::move(server)](
                      std::unique_ptr<control_plane::IHandlerChainFactory> handler_factory,
                      const config::IPCConfig&,
                      ipc::message_passing::AuthorizationCallback auth,
                      ipc::message_passing::DisconnectCleanupCallback clean) mutable {
            EXPECT_NE(handler_factory, nullptr);
            authorization = std::move(auth);
            cleanup = std::move(clean);
            return IDaemonComponentFactory::ControlServerResult{
                std::unique_ptr<control_plane::IControlServer>{std::move(server)}};
        });

    EXPECT_EQ(Initialize(), EXIT_SUCCESS);

    // An empty authorization callback makes the server deny every client.
    ASSERT_TRUE(authorization);
    const auto authorized = authorization(1000U, 1000U);
    ASSERT_TRUE(authorized.has_value());
    EXPECT_TRUE(authorized.value());

    // The cleanup behaviour itself is covered by disconnect_cleanup_callback_test.cpp.
    ASSERT_TRUE(cleanup);
    EXPECT_TRUE(cleanup(common::ClientId{42U}).has_value());
}

TEST_F(CryptoDaemonTest, RunServesUntilStopIsRequestedThenStopsServer)
{
    MockControlServer& server = ProvideServer();
    EXPECT_CALL(server, Start()).Times(1);
    ASSERT_EQ(Initialize(), EXIT_SUCCESS);

    {
        InSequence sequence;
        EXPECT_CALL(server, Stop()).Times(1);
        EXPECT_CALL(server, WaitForTermination()).Times(1);
    }

    score::cpp::stop_source stop_source;
    auto run_result = std::async(std::launch::async, [this, token = stop_source.get_token()]() {
        return m_daemon->Run(token);
    });

    EXPECT_EQ(run_result.wait_for(std::chrono::milliseconds(100)), std::future_status::timeout);

    stop_source.request_stop();
    const auto status = run_result.wait_for(std::chrono::seconds(5));
    EXPECT_EQ(status, std::future_status::ready);
    if (status == std::future_status::ready)
    {
        EXPECT_EQ(run_result.get(), EXIT_SUCCESS);
    }
}

TEST_F(CryptoDaemonTest, RunFailsWithoutSuccessfulInitialize)
{
    EXPECT_EQ(RunWithStoppedToken(), EXIT_FAILURE);
}

TEST_F(CryptoDaemonTest, DestructorStopsServerThatRunDidNotStop)
{
    MockControlServer& server = ProvideServer();
    ASSERT_EQ(Initialize(), EXIT_SUCCESS);

    {
        InSequence sequence;
        EXPECT_CALL(server, Stop()).Times(1);
        EXPECT_CALL(server, WaitForTermination()).Times(1);
    }

    m_daemon.reset();
}

}  // namespace
}  // namespace score::crypto::daemon
