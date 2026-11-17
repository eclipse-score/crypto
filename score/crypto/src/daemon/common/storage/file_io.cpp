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
#include "score/crypto/src/daemon/common/storage/file_io.hpp"

#include "score/filesystem/error.h"
#include "score/filesystem/filestream/file_factory.h"
#include "score/filesystem/filestream/file_stream.h"
#include "score/filesystem/filesystem.h"
#include "score/mw/log/logging.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace score::crypto::daemon::common::storage
{
namespace
{

/// Closes a POSIX file descriptor when it goes out of scope.
class FdGuard
{
  public:
    explicit FdGuard(int fd) noexcept : m_fd{fd} {}
    ~FdGuard()
    {
        if (m_fd >= 0)
        {
            static_cast<void>(::close(m_fd));
        }
    }

    FdGuard(const FdGuard&) = delete;
    FdGuard& operator=(const FdGuard&) = delete;
    FdGuard(FdGuard&& other) noexcept : m_fd{other.m_fd}
    {
        other.m_fd = -1;
    }
    FdGuard& operator=(FdGuard&&) = delete;

    [[nodiscard]] int Get() const noexcept
    {
        return m_fd;
    }

    /// Close the descriptor held so far, if any, and take over @p fd.
    void Reset(int fd) noexcept
    {
        if (m_fd >= 0)
        {
            static_cast<void>(::close(m_fd));
        }
        m_fd = fd;
    }

    /// Hand the descriptor over to the caller, who closes it from now on.
    [[nodiscard]] int Release() noexcept
    {
        const int fd = m_fd;
        m_fd = -1;
        return fd;
    }

    /// Close now and report whether the close succeeded.
    [[nodiscard]] bool Close() noexcept
    {
        const int fd = m_fd;
        m_fd = -1;
        return ::close(fd) == 0;
    }

  private:
    int m_fd;
};

/// Log a failed step of @p operation and return @p code.
///
/// @p error_number is the errno of the failing system call, captured by the caller right
/// after that call. Pass kNoErrno for a check or a call that does not set errno, so no
/// stale value is logged.
constexpr int kNoErrno = 0;
score::crypto::Expected<std::monostate, DaemonErrorCode> StepFailed(std::string_view operation,
                                                                    std::string_view step,
                                                                    DaemonErrorCode code,
                                                                    int error_number)
{
    if (error_number != kNoErrno)
    {
        score::mw::log::LogError() << "[FILE_IO] " << operation << ": " << step << " failed (errno " << error_number
                                   << ", error " << static_cast<int>(code) << ")";
    }
    else
    {
        score::mw::log::LogError() << "[FILE_IO] " << operation << ": " << step << " failed (error "
                                   << static_cast<int>(code) << ")";
    }
    return score::crypto::make_unexpected(code);
}

/// A path split into the directory that holds the entry and the entry's name.
struct SplitPath
{
    std::string directory;
    std::string name;
};

SplitPath Split(const std::string& path)
{
    const auto slash = path.find_last_of('/');
    if (slash == std::string::npos)
    {
        return SplitPath{".", path};
    }
    return SplitPath{(slash == 0U) ? std::string{"/"} : path.substr(0U, slash), path.substr(slash + 1U)};
}

/// The outcome of opening a directory: its descriptor, or the errno of the step that failed.
struct OpenedDirectory
{
    FdGuard fd;
    int error_number;
};

/// Open @p directory one component at a time and return a descriptor to it. Every later
/// step works relative to that descriptor, so a rename or a symbolic link swapped into the
/// path while an operation runs cannot redirect it.
///
/// With @p create, a missing component is created with mode 0700 (set explicitly, so the
/// umask cannot narrow it), and the directory that received it is flushed, so every new
/// entry of the chain is durable and not only the last one.
OpenedDirectory OpenDirectory(const std::string& directory, bool create)
{
    constexpr int kDirectoryFlags = O_RDONLY | O_DIRECTORY | O_CLOEXEC;
    const bool absolute = !directory.empty() && (directory.front() == '/');
    FdGuard current{::open(absolute ? "/" : ".", kDirectoryFlags)};
    if (current.Get() < 0)
    {
        return OpenedDirectory{FdGuard{-1}, errno};
    }

    std::size_t begin = 0U;
    while (begin < directory.size())
    {
        auto end = directory.find('/', begin);
        if (end == std::string::npos)
        {
            end = directory.size();
        }
        const std::string component = directory.substr(begin, end - begin);
        begin = end + 1U;
        if (component.empty() || (component == "."))
        {
            continue;
        }

        int next = ::openat(current.Get(), component.c_str(), kDirectoryFlags);
        if ((next < 0) && (errno == ENOENT) && create)
        {
            const bool made = ::mkdirat(current.Get(), component.c_str(), S_IRWXU) == 0;
            if (!made && (errno != EEXIST))
            {
                return OpenedDirectory{FdGuard{-1}, errno};
            }
            FdGuard created{::openat(current.Get(), component.c_str(), kDirectoryFlags)};
            if (created.Get() < 0)
            {
                return OpenedDirectory{FdGuard{-1}, errno};
            }
            if (made && ((::fchmod(created.Get(), S_IRWXU) != 0) || (::fsync(current.Get()) != 0)))
            {
                return OpenedDirectory{FdGuard{-1}, errno};
            }
            current.Reset(created.Release());
            continue;
        }
        if (next < 0)
        {
            return OpenedDirectory{FdGuard{-1}, errno};
        }
        current.Reset(next);
    }
    return OpenedDirectory{std::move(current), kNoErrno};
}

/// A key directory must be one nobody else can change: owned by this process's user or by
/// root, and not writable by other users. Otherwise another user could plant or swap the
/// entries this code overwrites and removes.
bool IsTrustedDirectory(int directory_fd) noexcept
{
    struct stat status{};
    if (::fstat(directory_fd, &status) != 0)
    {
        return false;
    }
    const bool owned = (status.st_uid == ::geteuid()) || (status.st_uid == 0U);
    return S_ISDIR(status.st_mode) && owned && ((status.st_mode & S_IWOTH) == 0U);
}

/// Write zeros over the first @p size bytes of the open file @p fd.
bool OverwriteWithZeros(int fd, off_t size) noexcept
{
    constexpr std::size_t kChunkSize = 4096U;
    const std::array<std::uint8_t, kChunkSize> zeros{};

    off_t offset = 0;
    while (offset < size)
    {
        const auto remaining = static_cast<std::size_t>(size - offset);
        const std::size_t chunk = remaining < kChunkSize ? remaining : kChunkSize;
        const ssize_t written = ::pwrite(fd, zeros.data(), chunk, offset);
        if (written < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return false;
        }
        if (written == 0)
        {
            return false;
        }
        offset += static_cast<off_t>(written);
    }
    return true;
}

/// Flush the entries of the open directory @p directory_fd. Every failure counts, EINVAL
/// included: a file system that cannot flush a directory gives no durability guarantee.
bool SyncDirectory(int directory_fd) noexcept
{
    return ::fsync(directory_fd) == 0;
}

/// Open the regular file @p name in @p directory_fd for writing, without following a
/// symbolic link and without blocking on a named pipe.
///
/// A key file the umask left without owner write permission (0400 after a 0277 umask) is
/// made writable again first, through a read-only descriptor checked to be a regular file
/// owned by this user, so it can still be erased.
int OpenForErase(int directory_fd, const std::string& name) noexcept
{
    // O_NOFOLLOW: never overwrite the target of a symbolic link placed where the key file is expected.
    // O_NONBLOCK: a named pipe at this name would otherwise block open() until a reader appears;
    // it has no effect on writes to a regular file.
    constexpr int kFlags = O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK;
    const int fd = ::openat(directory_fd, name.c_str(), O_WRONLY | kFlags);
    if ((fd >= 0) || (errno != EACCES))
    {
        return fd;
    }

    FdGuard reader{::openat(directory_fd, name.c_str(), O_RDONLY | kFlags)};
    struct stat status{};
    if ((reader.Get() < 0) || (::fstat(reader.Get(), &status) != 0) || !S_ISREG(status.st_mode) ||
        (status.st_uid != ::geteuid()) || (::fchmod(reader.Get(), S_IRUSR | S_IWUSR) != 0))
    {
        errno = EACCES;
        return -1;
    }
    return ::openat(directory_fd, name.c_str(), O_WRONLY | kFlags);
}

/// Securely erase the file @p name in the open directory @p directory_fd: overwrite it with
/// zeros in place, flush, and remove the name. Does not flush the directory; the caller
/// does that once for all names it removed.
///
/// Before the name is removed it is checked to still refer to the file just overwritten, so
/// an entry swapped in meanwhile is never removed in its place.
score::crypto::Expected<std::monostate, DaemonErrorCode> EraseEntry(std::string_view operation,
                                                                    int directory_fd,
                                                                    const std::string& name,
                                                                    std::size_t max_size)
{
    FdGuard fd{OpenForErase(directory_fd, name)};
    if (fd.Get() < 0)
    {
        const int open_errno = errno;
        if (open_errno == ENOENT)
        {
            return std::monostate{};
        }
        if ((open_errno == ELOOP) || (open_errno == EISDIR) || (open_errno == ENXIO))
        {
            return StepFailed(operation, "open (not a regular file)", DaemonErrorCode::kInvalidArgument, open_errno);
        }
        return StepFailed(operation, "open", DaemonErrorCode::kPersistFailed, open_errno);
    }

    struct stat file_status{};
    if (::fstat(fd.Get(), &file_status) != 0)
    {
        return StepFailed(operation, "fstat", DaemonErrorCode::kPersistFailed, errno);
    }
    if (!S_ISREG(file_status.st_mode))
    {
        return StepFailed(operation, "type check (not a regular file)", DaemonErrorCode::kInvalidArgument, kNoErrno);
    }
    if (static_cast<std::uintmax_t>(file_status.st_size) > max_size)
    {
        return StepFailed(
            operation, "size check (file larger than allowed)", DaemonErrorCode::kInvalidArgument, kNoErrno);
    }

    if (!OverwriteWithZeros(fd.Get(), file_status.st_size))
    {
        return StepFailed(operation, "overwrite", DaemonErrorCode::kPersistFailed, errno);
    }
    // Without fsync the zeros may still sit in the page cache when the file is unlinked,
    // and the kernel is then free to drop them without ever writing them to the device.
    if (::fsync(fd.Get()) != 0)
    {
        return StepFailed(operation, "fsync", DaemonErrorCode::kPersistFailed, errno);
    }
    if (!fd.Close())
    {
        return StepFailed(operation, "close", DaemonErrorCode::kPersistFailed, errno);
    }

    struct stat entry_status{};
    if (::fstatat(directory_fd, name.c_str(), &entry_status, AT_SYMLINK_NOFOLLOW) != 0)
    {
        const int stat_errno = errno;
        if (stat_errno == ENOENT)
        {
            return std::monostate{};
        }
        return StepFailed(operation, "fstatat", DaemonErrorCode::kPersistFailed, stat_errno);
    }
    if ((entry_status.st_dev != file_status.st_dev) || (entry_status.st_ino != file_status.st_ino))
    {
        return StepFailed(
            operation, "identity check (entry replaced during erase)", DaemonErrorCode::kPersistFailed, kNoErrno);
    }
    if ((::unlinkat(directory_fd, name.c_str(), 0) != 0) && (errno != ENOENT))
    {
        return StepFailed(operation, "remove", DaemonErrorCode::kPersistFailed, errno);
    }
    return std::monostate{};
}

/// Largest leftover temporary file a store erases. A temporary file holds one key, far
/// smaller than this; the limit only keeps an unrelated large file from being wiped.
constexpr std::size_t kMaxTemporaryFileSize = 1024U * 1024U;

/// Marker between a key file's name and the suffix of its temporary files.
constexpr std::string_view kTemporaryMarker = ".tmp.";

/// The prefix of the temporary files of key file @p name; with @p process_id, only those
/// created by that process.
std::string TemporaryPrefixFor(const std::string& name, pid_t process_id)
{
    std::ostringstream prefix;
    prefix << name << kTemporaryMarker;
    if (process_id > 0)
    {
        prefix << process_id << '.';
    }
    return prefix.str();
}

/// A temporary name for key file @p name, unique per call: the process id and 128 bits from
/// std::random_device, the operating system's entropy source, so the name cannot be
/// predicted from earlier ones.
std::string TemporaryNameFor(const std::string& name)
{
    std::random_device entropy{};
    std::ostringstream suffix;
    suffix << std::hex;
    for (int word = 0; word < 4; ++word)
    {
        suffix << static_cast<std::uint32_t>(entropy());
    }
    return TemporaryPrefixFor(name, ::getpid()) + suffix.str();
}

/// Securely erase the temporary files of key file @p name left in @p directory_fd, for
/// example by a process that crashed between writing and publishing a key. Temporary files
/// of the process @p skip_process_id are left alone (pass 0 to erase all of them).
score::crypto::Expected<std::monostate, DaemonErrorCode> EraseLeftoverTemporaries(std::string_view operation,
                                                                                  int directory_fd,
                                                                                  const std::string& name,
                                                                                  std::size_t max_size,
                                                                                  pid_t skip_process_id)
{
    const std::string prefix = TemporaryPrefixFor(name, 0);
    const std::string skipped = (skip_process_id > 0) ? TemporaryPrefixFor(name, skip_process_id) : std::string{};

    std::vector<std::string> leftovers;
    {
        const int list_fd = ::openat(directory_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (list_fd < 0)
        {
            return StepFailed(operation, "open directory listing", DaemonErrorCode::kPersistFailed, errno);
        }
        DIR* const listing = ::fdopendir(list_fd);
        if (listing == nullptr)
        {
            const int list_errno = errno;
            static_cast<void>(::close(list_fd));
            return StepFailed(operation, "open directory listing", DaemonErrorCode::kPersistFailed, list_errno);
        }
        errno = 0;
        while (const dirent* const entry = ::readdir(listing))
        {
            const std::string_view entry_name{entry->d_name};
            if ((entry_name.substr(0U, prefix.size()) == prefix) &&
                (skipped.empty() || (entry_name.substr(0U, skipped.size()) != skipped)))
            {
                leftovers.emplace_back(entry_name);
            }
        }
        const int read_errno = errno;
        static_cast<void>(::closedir(listing));
        if (read_errno != 0)
        {
            return StepFailed(operation, "read directory listing", DaemonErrorCode::kPersistFailed, read_errno);
        }
    }

    score::crypto::Expected<std::monostate, DaemonErrorCode> result{std::monostate{}};
    for (const auto& leftover : leftovers)
    {
        auto erased = EraseEntry(operation, directory_fd, leftover, max_size);
        if (!erased.has_value() && result.has_value())
        {
            result = erased;
        }
    }
    return result;
}

/// Log that a cleanup step after a failure did not succeed, and what it leaves behind.
void CleanupFailed(std::string_view operation, std::string_view step, std::string_view consequence)
{
    score::mw::log::LogError() << "[FILE_IO] " << operation << ": cleanup step '" << step << "' failed; "
                               << consequence;
}

}  // namespace

score::crypto::Expected<std::vector<std::uint8_t>, DaemonErrorCode> ReadFile(const std::string& path,
                                                                             std::size_t max_size)
{
    const auto exists = FileExists(path);
    if (!exists.has_value())
    {
        return score::crypto::make_unexpected(exists.error());
    }
    if (!exists.value())
    {
        return score::crypto::make_unexpected(DaemonErrorCode::kResourceNotAllocated);
    }

    score::filesystem::FileFactory factory{};
    auto open_result = factory.Open(score::filesystem::Path{path}, std::ios::binary | std::ios::in);
    if (!open_result.has_value())
    {
        return score::crypto::make_unexpected(open_result.error() ==
                                                      score::filesystem::ErrorCode::kFileOrDirectoryDoesNotExist
                                                  ? DaemonErrorCode::kResourceNotAllocated
                                                  : DaemonErrorCode::kInternalError);
    }

    auto& stream = *open_result.value();
    stream.seekg(0, std::ios::end);
    const auto size = stream.tellg();
    if (size <= 0 || static_cast<std::uintmax_t>(size) > max_size)
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    stream.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
    stream.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!stream)
        return score::crypto::make_unexpected(DaemonErrorCode::kInternalError);
    return data;
}

score::crypto::Expected<std::monostate, DaemonErrorCode> WriteFile(const std::string& path,
                                                                   score::crypto::span<const std::uint8_t> data)
{
    if (path.empty() || data.empty())
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);

    const score::filesystem::Path target_path{path};
    score::filesystem::StandardFilesystem fs{};
    const auto parent = target_path.ParentPath();
    if (!parent.Empty())
    {
        if (!fs.CreateDirectories(parent).has_value())
            return score::crypto::make_unexpected(DaemonErrorCode::kInternalError);
    }

    score::filesystem::FileFactory factory{};
    auto stream_result = factory.AtomicUpdate(target_path, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!stream_result.has_value())
        return score::crypto::make_unexpected(DaemonErrorCode::kPersistFailed);

    auto& stream = *stream_result.value();
    stream.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    stream.flush();
    if (!stream)
        // Stream is in a bad state; Close() (called by the destructor) will detect this
        // and clean up the temp file rather than renaming it.
        return score::crypto::make_unexpected(DaemonErrorCode::kPersistFailed);

    // Close() triggers the atomic rename — check it explicitly to confirm success.
    // The destructor calls Close() again on the way out; a second call on an already-closed
    // stream returns an error that the destructor ignores, which is safe.
    if (!stream_result.value()->Close().has_value())
        return score::crypto::make_unexpected(DaemonErrorCode::kPersistFailed);
    return std::monostate{};
}

score::crypto::Expected<bool, DaemonErrorCode> FileExists(const std::string& path)
{
    if (path.empty())
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);

    score::filesystem::StandardFilesystem fs{};
    const auto result = fs.IsRegularFile(score::filesystem::Path{path});
    if (!result.has_value())
    {
        if (result.error() == score::filesystem::ErrorCode::kFileOrDirectoryDoesNotExist)
            return false;
        return score::crypto::make_unexpected(DaemonErrorCode::kInternalError);
    }
    return result.value();
}

score::crypto::Expected<std::monostate, DaemonErrorCode> RemoveFile(const std::string& path)
{
    if (path.empty())
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    score::filesystem::StandardFilesystem fs{};
    const auto result = fs.Remove(score::filesystem::Path{path});
    if (!result.has_value())
    {
        const auto status = fs.Status(score::filesystem::Path{path});
        if (status.has_value() && status->Type() == score::filesystem::FileType::kNotFound)
            return std::monostate{};
        if (result.error() == score::filesystem::ErrorCode::kFileOrDirectoryDoesNotExist)
            return std::monostate{};
        return score::crypto::make_unexpected(DaemonErrorCode::kPersistFailed);
    }
    return std::monostate{};
}

// SecureEraseFile and CreateSecretFile use POSIX calls directly: score::filesystem has no
// positional write (pwrite), no fsync and no *at() calls, and all three are needed to
// overwrite the existing blocks durably inside one pinned directory.
score::crypto::Expected<std::monostate, DaemonErrorCode> SecureEraseFile(const std::string& path, std::size_t max_size)
{
    constexpr std::string_view kOperation = "SecureEraseFile";
    const auto split = Split(path);
    if (path.empty() || split.name.empty())
    {
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    }

    auto directory = OpenDirectory(split.directory, false);
    if (directory.fd.Get() < 0)
    {
        // No directory means no key file and no temporary file either.
        if (directory.error_number == ENOENT)
        {
            return std::monostate{};
        }
        return StepFailed(kOperation, "open directory", DaemonErrorCode::kPersistFailed, directory.error_number);
    }
    if (!IsTrustedDirectory(directory.fd.Get()))
    {
        return StepFailed(kOperation,
                          "directory check (not owned by this user or root, or writable by others)",
                          DaemonErrorCode::kInvalidArgument,
                          kNoErrno);
    }

    const auto erased = EraseEntry(kOperation, directory.fd.Get(), split.name, max_size);
    if (!erased.has_value())
    {
        return erased;
    }
    // A store interrupted between writing and publishing leaves the key in a temporary file.
    const auto leftovers = EraseLeftoverTemporaries(kOperation, directory.fd.Get(), split.name, max_size, 0);
    if (!leftovers.has_value())
    {
        return leftovers;
    }

    // Make the unlink durable, also when the file was already gone: an earlier call may have
    // removed it and then failed here, and this retry must finish what that one left open.
    // Without it a power loss can bring the file back zero-filled, and the slot then reads
    // as occupied by an all-zero key.
    if (!SyncDirectory(directory.fd.Get()))
    {
        return StepFailed(kOperation, "directory fsync", DaemonErrorCode::kPersistFailed, errno);
    }
    return std::monostate{};
}

score::crypto::Expected<std::monostate, DaemonErrorCode> CreateSecretFile(const std::string& path,
                                                                          score::crypto::span<const std::uint8_t> data)
{
    constexpr std::string_view kOperation = "CreateSecretFile";
    const auto split = Split(path);
    if (path.empty() || split.name.empty() || data.empty())
    {
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    }

    auto directory = OpenDirectory(split.directory, true);
    if (directory.fd.Get() < 0)
    {
        return StepFailed(
            kOperation, "open or create directory", DaemonErrorCode::kPersistFailed, directory.error_number);
    }
    const int dir_fd = directory.fd.Get();
    if (!IsTrustedDirectory(dir_fd))
    {
        return StepFailed(kOperation,
                          "directory check (not owned by this user or root, or writable by others)",
                          DaemonErrorCode::kInvalidArgument,
                          kNoErrno);
    }

    // Temporary files of an earlier, crashed process still hold key material; erase them.
    // This process's own may belong to a store running on another thread, so they stay.
    if (!EraseLeftoverTemporaries(kOperation, dir_fd, split.name, kMaxTemporaryFileSize, ::getpid()).has_value())
    {
        CleanupFailed(kOperation, "erase leftover temporary files", "they remain until the slot is cleared");
    }

    // O_EXCL: a stale or planted file (or link) at the temporary name is never reused. The
    // name is random, so a collision is not expected; should one happen anyway, try a fresh one.
    constexpr int kTemporaryNameAttempts = 8;
    std::string temp_name;
    FdGuard fd{-1};
    int create_errno = kNoErrno;
    for (int attempt = 0; (attempt < kTemporaryNameAttempts) && (fd.Get() < 0); ++attempt)
    {
        temp_name = TemporaryNameFor(split.name);
        fd.Reset(::openat(
            dir_fd, temp_name.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR));
        create_errno = errno;
        if ((fd.Get() < 0) && (create_errno != EEXIST))
        {
            break;
        }
    }
    if (fd.Get() < 0)
    {
        return StepFailed(kOperation, "create temporary file", DaemonErrorCode::kPersistFailed, create_errno);
    }

    // Anything that fails before the file is published leaves key bytes in the temporary
    // file; erase it. The errno is captured by the caller before the erase can change it.
    const auto discard_temp = [&](std::string_view step, DaemonErrorCode code, int error_number) {
        auto result = StepFailed(kOperation, step, code, error_number);
        fd.Reset(-1);
        if (!EraseEntry(kOperation, dir_fd, temp_name, data.size()).has_value())
        {
            CleanupFailed(kOperation,
                          "erase temporary file",
                          "it still holds the key and is erased when the slot is cleared or on the next store");
        }
        return result;
    };

    // The mode given to open() is narrowed by the umask (0277 would leave 0400, a file this
    // process could no longer open for erasing). Set the owner-only mode explicitly.
    if (::fchmod(fd.Get(), S_IRUSR | S_IWUSR) != 0)
    {
        return discard_temp("set mode", DaemonErrorCode::kPersistFailed, errno);
    }

    std::size_t written_total = 0U;
    while (written_total < data.size())
    {
        const ssize_t written = ::write(fd.Get(), data.data() + written_total, data.size() - written_total);
        if (written < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return discard_temp("write", DaemonErrorCode::kPersistFailed, errno);
        }
        if (written == 0)
        {
            return discard_temp("write", DaemonErrorCode::kPersistFailed, kNoErrno);
        }
        written_total += static_cast<std::size_t>(written);
    }
    if (::fsync(fd.Get()) != 0)
    {
        return discard_temp("fsync", DaemonErrorCode::kPersistFailed, errno);
    }
    if (!fd.Close())
    {
        return discard_temp("close", DaemonErrorCode::kPersistFailed, errno);
    }

    // linkat() publishes the complete file under its final name and fails with EEXIST when
    // that name is taken, so an occupied key file is never replaced, even by a concurrent writer.
    if (::linkat(dir_fd, temp_name.c_str(), dir_fd, split.name.c_str(), 0) != 0)
    {
        const int link_errno = errno;
        return discard_temp(
            "publish",
            (link_errno == EEXIST) ? DaemonErrorCode::kKeySlotOccupied : DaemonErrorCode::kPersistFailed,
            link_errno);
    }

    // The key file now holds the bytes; the temporary name is only a second link to the same
    // blocks, so removing it must not overwrite them. The store succeeds only once both the
    // removal and the directory flush succeed.
    const char* failed_step = nullptr;
    int publish_errno = kNoErrno;
    if (::unlinkat(dir_fd, temp_name.c_str(), 0) != 0)
    {
        failed_step = "remove temporary name";
        publish_errno = errno;
    }
    else if (!SyncDirectory(dir_fd))
    {
        failed_step = "directory fsync";
        publish_errno = errno;
    }
    if (failed_step == nullptr)
    {
        return std::monostate{};
    }

    // Roll back, so a failed store leaves the slot empty and can simply be retried: erase the
    // key through its final name (both names share the same blocks), remove the temporary
    // name if it is still there, and flush the directory.
    auto result = StepFailed(kOperation, failed_step, DaemonErrorCode::kPersistFailed, publish_errno);
    if (!EraseEntry(kOperation, dir_fd, split.name, data.size()).has_value())
    {
        CleanupFailed(kOperation, "erase published key", "the slot stays occupied until it is cleared");
    }
    if ((::unlinkat(dir_fd, temp_name.c_str(), 0) != 0) && (errno != ENOENT))
    {
        CleanupFailed(
            kOperation, "remove temporary name", "it is erased when the slot is cleared or on the next store");
    }
    if (!SyncDirectory(dir_fd))
    {
        CleanupFailed(kOperation, "directory fsync", "the rollback may not survive a power loss");
    }
    return result;
}

}  // namespace score::crypto::daemon::common::storage
