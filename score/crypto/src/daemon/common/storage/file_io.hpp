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

#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_FILE_IO_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_FILE_IO_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <variant>
#include <vector>

namespace score::crypto::daemon::common::storage
{

/// Read the entire binary contents of @p path into a byte vector.
///
/// @param path     Absolute or relative path to the file.
/// @param max_size Maximum accepted file size in bytes. Returns kInvalidArgument
///                 if the file is empty or exceeds this limit.
/// @return Byte vector on success; kResourceNotAllocated if the file is absent,
///         kInvalidArgument if size is out of range, kInternalError if the file
///         cannot be opened for another reason or on a partial read.
[[nodiscard]] score::crypto::Expected<std::vector<std::uint8_t>, DaemonErrorCode> ReadFile(const std::string& path,
                                                                                           std::size_t max_size);

/// Write @p data to @p path atomically via a temporary file and rename.
///
/// Creates parent directories if they do not exist. Writes to a sibling
/// <path>.tmp first, then renames atomically. The temporary file is removed
/// on rename failure.
///
/// @return std::monostate on success; kInvalidArgument if path or data is
///         empty, kInternalError if the directory cannot be created,
///         kPersistFailed on write or rename failure.
[[nodiscard]] score::crypto::Expected<std::monostate, DaemonErrorCode> WriteFile(
    const std::string& path,
    score::crypto::span<const std::uint8_t> data);

/// Write primitive used by the storage components that persist files. Production code uses
/// WriteFile. A test substitutes a writer to make a write succeed or fail at a chosen point.
using FileWriter = std::function<score::crypto::Expected<std::monostate, DaemonErrorCode>(
    const std::string& path,
    score::crypto::span<const std::uint8_t> data)>;

/// Check whether @p path refers to an existing regular file.
///
/// Returns false for missing paths, directories, symlinks to non-existent
/// targets, and other non-regular-file entries. Filesystem errors are returned
/// as failures instead of being reported as absence.
[[nodiscard]] score::crypto::Expected<bool, DaemonErrorCode> FileExists(const std::string& path);

/// Remove the file at @p path.
///
/// Idempotent: returns success if the file does not exist.
///
/// @return std::monostate on success or if the file was already absent;
///         kInvalidArgument if path is empty, kPersistFailed on a filesystem error.
[[nodiscard]] score::crypto::Expected<std::monostate, DaemonErrorCode> RemoveFile(const std::string& path);

/// Overwrite the contents of the file at @p path with zeros in place, flush them to
/// the storage device, remove the file, then flush the directory that held it.
///
/// Used to delete persisted key material: unlinking alone leaves the bytes on the
/// device until the blocks are reused. The overwrite goes to the file's existing
/// blocks (no truncation, no temporary file), so it reaches the data the file held.
/// On storage that remaps writes (flash translation layers, copy-on-write or
/// log-structured file systems) an in-place overwrite cannot guarantee that every
/// physical copy is gone; keys that need that guarantee belong in an HSM or TEE, or
/// must be encrypted at rest.
///
/// The directory is opened once and every step works relative to that descriptor, so the
/// path cannot be redirected while the erase runs. The directory must be owned by this
/// process's user or by root and must not be writable by other users; otherwise nothing is
/// erased. Leftover temporary files of an interrupted CreateSecretFile for the same name
/// (<name>.tmp.*) are erased too. Before a name is removed it is checked to still refer to
/// the file just overwritten, so an entry swapped in meanwhile is never removed.
///
/// Idempotent: returns success if the file does not exist, and still flushes the directory
/// then, so a retry after a failed directory flush completes the earlier removal. Only a
/// regular file is erased: a symbolic link at @p path is not followed, so the target of a
/// link placed where a key file is expected is never overwritten, and a named pipe or device
/// is refused without blocking. A file larger than @p max_size is refused as well, so a
/// misconfigured path cannot destroy an unrelated large file. A key file the umask left
/// without owner write permission is made writable again and erased. Until the file is
/// removed, a failure leaves it in place, so the deletion can be retried.
///
/// @param path     Path to the file to erase.
/// @param max_size Largest file, in bytes, this call may erase.
/// @return std::monostate on success or if the file was already absent;
///         kInvalidArgument if path is empty, is a symbolic link, is not a regular file
///         or is larger than max_size, or its directory is not trusted; kPersistFailed if
///         the file cannot be opened, overwritten, flushed or removed, was replaced during
///         the erase, or its directory cannot be flushed.
[[nodiscard]] score::crypto::Expected<std::monostate, DaemonErrorCode> SecureEraseFile(const std::string& path,
                                                                                       std::size_t max_size);

/// Create a new file at @p path holding @p data, readable and writable by the owner only (0600),
/// and fail if a file already exists there.
///
/// Used to persist key material. The bytes are written to a sibling temporary file created
/// exclusively with mode 0600 (set explicitly, so the umask cannot narrow it, and never
/// world-readable, not even briefly), flushed with fsync, then published under @p path with
/// link(), which fails atomically when @p path already exists, so an occupied key file is never
/// replaced. Finally the temporary name is removed and the directory is flushed. All steps work
/// relative to one descriptor of the directory, which must be owned by this process's user or by
/// root and not writable by other users.
///
/// Missing parent directories are created with mode 0700, and the directory that received each
/// new one is flushed, so the whole chain is durable. The temporary name carries the process id
/// and a 128-bit suffix from std::random_device; a taken name is retried with a fresh one.
/// Temporary files that an earlier, crashed process left for the same name are erased first.
///
/// A failed call leaves no key behind: before publishing, the temporary file is securely
/// erased; after publishing, if the temporary name cannot be removed or the directory cannot
/// be flushed, the key is erased again through its final name, so the slot is empty and the
/// store can be retried. A cleanup step that fails is logged; what it leaves is erased by the
/// next SecureEraseFile of @p path.
///
/// @return std::monostate on success; kInvalidArgument if path or data is empty or the
///         directory is not trusted; kKeySlotOccupied if a file (or link) already exists at
///         path; kPersistFailed if the directory, the temporary file or the final name cannot
///         be created, written or flushed.
[[nodiscard]] score::crypto::Expected<std::monostate, DaemonErrorCode> CreateSecretFile(
    const std::string& path,
    score::crypto::span<const std::uint8_t> data);

}  // namespace score::crypto::daemon::common::storage

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_FILE_IO_HPP
