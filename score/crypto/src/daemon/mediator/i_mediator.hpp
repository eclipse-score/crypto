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

#ifndef SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_I_MEDIATOR_HPP
#define SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_I_MEDIATOR_HPP

#include <memory>
#include <string>
#include <utility>

#include "score/crypto/src/daemon/common/context/i_context_factory.hpp"
#include "score/crypto/src/daemon/common/context/i_mediator_query.hpp"
#include "score/crypto/src/daemon/common/context/i_mediator_registrar.hpp"
#include "score/crypto/src/daemon/common/context/i_resource_resolver.hpp"
#include "score/crypto/src/daemon/common/context/keyed_registry.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/control_plane/i_request_handler.hpp"
#include "score/crypto/src/daemon/data_manager/i_data_manager.hpp"
#include "score/crypto/src/daemon/data_plane/i_shm_registry.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"
#include "score/crypto/types/common.hpp"

namespace score::crypto::daemon::mediator
{

class HandlerSelector;
class ContextAssembler;

using common::ContextFactoryRegistry;
using common::MediatorQueryRegistry;
using common::ResourceResolverRegistry;

/// @brief Collaborators a mediator is built from.
///
/// The registries, selector and assembler are shared by every caller of the mediator. The registries
/// are passed as const because they are not changed once the daemon starts. A registry left null is
/// treated as empty. The selector and assembler are required for context creation.
struct MediatorDependencies
{
    /// Data nodes of every client: contexts, resolved resources and shared-memory objects.
    daemon::data_manager::IDataManager::Sptr data_manager;
    /// Registered providers; used to select the provider of a shared-memory object.
    daemon::provider::ProviderManager::Sptr provider_manager;
    /// Shared-memory quota bookkeeping, shared by every connection.
    daemon::data_plane::IShmRegistry::Sptr shm_registry;
    /// Resolver for each resource type of RESOLVE_RESOURCE; null is treated as empty.
    std::shared_ptr<const ResourceResolverRegistry> resource_resolvers;
    /// Query for each mediator operation code the mediator does not implement; null is treated as empty.
    std::shared_ptr<const MediatorQueryRegistry> mediator_queries;
    /// Chooses the handler of a new context, from a registered factory or a provider. Required.
    std::shared_ptr<const HandlerSelector> handler_selector;
    /// Creates the context node, binds the key and initializes the handler. Required.
    std::shared_ptr<const ContextAssembler> assembler;
};

/**
 * @interface IMediator
 * @brief Interface for mediating API requests in the crypto daemon.
 *
 * The IMediator interface, implementation shall classify the type of the
 * crypto operation the incoming request pertains to and delegate it to the
 * appropriate handler within the crypto daemon. It inherits from IRequestHandler
 * to participate in the chain of responsibility pattern.
 */
class IMediator : public score::crypto::daemon::control_plane::IRequestHandler
{
  public:
    /// @brief Take over the collaborators of the mediator.
    /// @param deps Collaborators; a null registry is replaced by an empty one, while the handler selector and the
    ///             assembler must not be null.
    explicit IMediator(MediatorDependencies deps)
        : m_data_manager(std::move(deps.data_manager)),
          m_provider_manager(std::move(deps.provider_manager)),
          m_shm_registry(std::move(deps.shm_registry)),
          m_resource_resolvers(common::OrEmpty(std::move(deps.resource_resolvers))),
          m_mediator_queries(common::OrEmpty(std::move(deps.mediator_queries))),
          m_handler_selector(std::move(deps.handler_selector)),
          m_assembler(std::move(deps.assembler))
    {
    }

    /**
     * @brief Virtual destructor.
     */
    virtual ~IMediator() = default;

    // Delete copy and move operations
    IMediator(const IMediator&) = delete;
    IMediator& operator=(const IMediator&) = delete;
    IMediator(IMediator&&) = delete;
    IMediator& operator=(IMediator&&) = delete;

    /**
     * @brief Processes a control request and generates a corresponding response.
     *
     * One mediator serves every connection, so this may be called from several threads at once.
     *
     * @param request The control request to be processed, containing command and
     * parameters.
     * @return ControlResponse The response generated after processing the
     * request.
     */
    virtual score::crypto::daemon::control_plane::ControlResponse processRequest(
        score::crypto::daemon::control_plane::ControlRequest& request) override = 0;

  protected:
    daemon::data_manager::IDataManager::Sptr m_data_manager;
    daemon::provider::ProviderManager::Sptr m_provider_manager;
    daemon::data_plane::IShmRegistry::Sptr m_shm_registry;
    std::shared_ptr<const ResourceResolverRegistry> m_resource_resolvers;
    std::shared_ptr<const MediatorQueryRegistry> m_mediator_queries;
    std::shared_ptr<const HandlerSelector> m_handler_selector;
    std::shared_ptr<const ContextAssembler> m_assembler;
};

}  // namespace score::crypto::daemon::mediator

#endif  // SCORE_CRYPTO_DAEMON_MEDIATOR_IMEDIATOR_HPP
