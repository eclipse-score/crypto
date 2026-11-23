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

#include "score/crypto/src/daemon/provider/score_provider/operations/mac/mac_executor.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/mac_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/src/handler_utils.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/mac/score_mac_handler.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::mac
{

namespace handler = ::score::crypto::daemon::provider::handler;
using common::DaemonErrorCode;
using common::RequestParameters;
using common::ResponseParameters;
using common::StreamOperationState;
using ::score::crypto::daemon::provider::handler::handler_utils::CheckAndGetSpan;
using ::score::crypto::daemon::provider::handler::handler_utils::ToSizeResponse;
using ::score::crypto::daemon::provider::handler::handler_utils::ValidateParameterCount;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

Expected<ResponseParameters, DaemonErrorCode> MacExecutor::Execute(ScoreMacHandler& handler,
                                                                   const common::OperationIdentifier& operationId,
                                                                   RequestParameters& request)
{
    if (operationId.operationAction == handler::mac_handler_operations::MAC_GET_SIZE)
    {
        return GetMacSize(handler, request);
    }

    if (operationId.operationAction == handler::mac_handler_operations::MAC_RESET)
    {
        auto res = ExecuteReset(handler, request);
        if (!res.has_value())
        {
            return make_unexpected(res.error());
        }
        return ResponseParameters{};
    }

    if (operationId.operationAction == handler::mac_handler_operations::MAC_SS)
    {
        if (handler.GetOperationState() == StreamOperationState::STREAM_ACTIVE)
        {
            return make_unexpected(DaemonErrorCode::kOperationInProgress);
        }
        auto result = ExecuteSingleShot(handler, request);
        // A single-shot always ends the stream, so the context is left reusable
        // even when the operation failed part-way through.
        handler.SetOperationState(StreamOperationState::IDLE);
        return result;
    }

    if (operationId.operationAction == handler::mac_handler_operations::MAC_VERIFY)
    {
        if (handler.GetOperationState() == StreamOperationState::IDLE)
        {
            return make_unexpected(DaemonErrorCode::kStreamNotInitialized);
        }
        auto result = ExecuteVerify(handler, request);
        if (result.has_value())
        {
            handler.SetOperationState(StreamOperationState::IDLE);
        }
        return result;
    }

    // Streaming operations: validate state machine transition
    StreamOperationState currentState = handler.GetOperationState();
    StreamOperationState nextState = StreamOperationState::IDLE;
    const auto validation = ValidateStreamTransition(operationId.operationAction, currentState, nextState);
    if (!validation.has_value())
    {
        return make_unexpected(validation.error());
    }

    if (operationId.operationAction == handler::mac_handler_operations::MAC_INIT)
    {
        auto result = ExecuteInit(handler, request);
        if (result.has_value())
        {
            handler.SetOperationState(nextState);
            return ResponseParameters{};
        }
        return make_unexpected(result.error());
    }

    if (operationId.operationAction == handler::mac_handler_operations::MAC_FINALIZE)
    {
        auto result = ExecuteFinalize(handler, request);
        if (result.has_value())
        {
            handler.SetOperationState(nextState);
        }
        return result;
    }

    if (operationId.operationAction == handler::mac_handler_operations::MAC_UPDATE)
    {
        auto result = ExecuteUpdate(handler, request);
        if (result.has_value())
        {
            handler.SetOperationState(nextState);
            return ResponseParameters{};
        }
        return make_unexpected(result.error());
    }

    return make_unexpected(DaemonErrorCode::kInvalidOperation);
}

// ---------------------------------------------------------------------------
// Operation implementations
// ---------------------------------------------------------------------------

Expected<std::monostate, DaemonErrorCode> MacExecutor::ExecuteInit(ScoreMacHandler& handler, RequestParameters& request)
{
    // request[0] = optional IV
    if (request.size() > 1U)
    {
        return make_unexpected(DaemonErrorCode::kInvalidArgument);
    }

    std::optional<score::cpp::span<const std::uint8_t>> iv;
    if (!request.empty())
    {
        const auto ivSpan = CheckAndGetSpan<const std::uint8_t>(request[0]);
        if (!ivSpan.has_value())
        {
            return make_unexpected(ivSpan.error());
        }
        iv.emplace(ivSpan.value());
    }
    return handler.InitMac(iv);
}

Expected<std::monostate, DaemonErrorCode> MacExecutor::ExecuteUpdate(ScoreMacHandler& handler,
                                                                     RequestParameters& request)
{
    // request[0] = data chunk
    const auto countResult = ValidateParameterCount(request, 1U);
    if (!countResult.has_value())
    {
        return make_unexpected(countResult.error());
    }

    // An empty chunk is valid input, and the MAC of an empty message is defined.
    const auto dataSpan = CheckAndGetSpan<const std::uint8_t>(request[0], true);
    if (!dataSpan.has_value())
    {
        return make_unexpected(dataSpan.error());
    }
    return handler.UpdateMac(dataSpan.value());
}

Expected<ResponseParameters, DaemonErrorCode> MacExecutor::ExecuteFinalize(ScoreMacHandler& handler,
                                                                           RequestParameters& request)
{
    // request[0] = tag output buffer, request[1] = optional final data chunk
    if (request.empty())
    {
        return make_unexpected(DaemonErrorCode::kInsufficientParameters);
    }
    if (request.size() > 2U)
    {
        return make_unexpected(DaemonErrorCode::kInvalidArgument);
    }

    const auto tagSpan = CheckAndGetSpan<std::uint8_t>(request[0]);
    if (!tagSpan.has_value())
    {
        return make_unexpected(tagSpan.error());
    }
    // Rejected before the trailing chunk enters the stream, so a retry with a larger buffer sees the same input.
    if (tagSpan.value().size() < handler.GetMacSize())
    {
        return make_unexpected(DaemonErrorCode::kInsufficientBufferSize);
    }

    if (request.size() > 1U)
    {
        const auto finalData = CheckAndGetSpan<const std::uint8_t>(request[1], true);
        if (!finalData.has_value())
        {
            return make_unexpected(finalData.error());
        }
        auto update = handler.UpdateMac(finalData.value());
        if (!update.has_value())
        {
            return make_unexpected(update.error());
        }
    }

    return ToSizeResponse(handler.FinalizeMac(tagSpan.value()));
}

Expected<ResponseParameters, DaemonErrorCode> MacExecutor::ExecuteVerify(ScoreMacHandler& handler,
                                                                         RequestParameters& request)
{
    // request[0] = expected tag
    const auto countResult = ValidateParameterCount(request, 1U);
    if (!countResult.has_value())
    {
        return make_unexpected(countResult.error());
    }

    const auto tagSpan = CheckAndGetSpan<const std::uint8_t>(request[0]);
    if (!tagSpan.has_value())
    {
        return make_unexpected(tagSpan.error());
    }

    auto matches = handler.VerifyMac(tagSpan.value());
    if (!matches.has_value())
    {
        return make_unexpected(matches.error());
    }

    ResponseParameters response;
    response.push_back(matches.value());
    return response;
}

Expected<ResponseParameters, DaemonErrorCode> MacExecutor::ExecuteSingleShot(ScoreMacHandler& handler,
                                                                             RequestParameters& request)
{
    // request[0] = data, request[1] = tag output buffer
    const auto countResult = ValidateParameterCount(request, 2U);
    if (!countResult.has_value())
    {
        return make_unexpected(countResult.error());
    }

    const auto dataSpan = CheckAndGetSpan<const std::uint8_t>(request[0], true);
    if (!dataSpan.has_value())
    {
        return make_unexpected(dataSpan.error());
    }
    const auto tagSpan = CheckAndGetSpan<std::uint8_t>(request[1]);
    if (!tagSpan.has_value())
    {
        return make_unexpected(tagSpan.error());
    }

    return ToSizeResponse(handler.SingleShotMac(dataSpan.value(), tagSpan.value()));
}

Expected<ResponseParameters, DaemonErrorCode> MacExecutor::GetMacSize(const ScoreMacHandler& handler,
                                                                      RequestParameters& /*request*/)
{
    return ToSizeResponse(handler.GetMacSize());
}

Expected<std::monostate, DaemonErrorCode> MacExecutor::ExecuteReset(ScoreMacHandler& handler,
                                                                    RequestParameters& /*request*/)
{
    return handler.Reset();
}

// ---------------------------------------------------------------------------
// Stream state machine
// ---------------------------------------------------------------------------

// static
Expected<std::monostate, DaemonErrorCode> MacExecutor::ValidateStreamTransition(const common::OperationAction action,
                                                                                const StreamOperationState currentState,
                                                                                StreamOperationState& nextState)
{
    const auto op = handler::mac_handler_operations::ToStreamOperation(action);
    if (!op.has_value())
    {
        return make_unexpected(DaemonErrorCode::kInvalidOperation);
    }
    // Finalize may follow Init directly: the empty message has a MAC.
    const auto result = handler::handler_utils::ValidateStreamOperationSequence(
        currentState, op.value(), true, DaemonErrorCode::kInvalidStreamOperation);
    if (!result.has_value())
    {
        return make_unexpected(result.error());
    }
    nextState = result.value();
    return std::monostate{};
}

}  // namespace score::crypto::daemon::provider::score_provider::operations::mac
