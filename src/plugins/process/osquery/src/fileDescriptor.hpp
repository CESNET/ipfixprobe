/**
 * @file
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @brief This file declares the FileDescriptor base classed used as wrapper for UNIX file
 * descriptors that manage its lifetime
 *
 * @copyright Copyright (c) 2024 CESNET, z.s.p.o.
 */

#pragma once

#include <string>

#include <unistd.h>

namespace ipxp::process::osquery {

/**
 * @brief Wrapper that owns and manages a file descriptor.
 *
 * It makes sure that the descriptor is closed, when the lifetime of the wrapper
 * instance goes out of scope.
 */
class FileDescriptor {
public:
	explicit FileDescriptor() noexcept;

	/**
	 * @brief Construct wrapper with given file descriptor.
	 * @param fileDescriptor File descriptor to take ownership
	 */
	explicit FileDescriptor(const int fileDescriptor) noexcept;

	explicit FileDescriptor(FileDescriptor&& other) noexcept;

	FileDescriptor& operator=(FileDescriptor&& other) noexcept;

	virtual ~FileDescriptor() noexcept;

	FileDescriptor(const FileDescriptor& other) = delete;

	/** @brief Test whether the wrapper holds a valid file descriptor. */
	operator bool() const noexcept;

	/** @brief Test whether the wrapper holds a valid file descriptor.
	 * @return True if holds valid file descriptor, false otherwise
	 */
	bool hasValue() const noexcept;

	/**
	 * @brief Get the managed file descriptor.
	 * @note It may return an invalid file descriptor if it doesn't hold any.
	 */
	operator int() const noexcept;

	/**
	 * @brief Get the managed file descriptor.
	 * @note It may return an invalid file descriptor if it doesn't hold any.
	 * @return Underlying file descriptor
	 */
	int get() const noexcept;

	/**
	 * @brief Return the managed file descriptor and release its ownership.
	 * @note It may return an invalid file descriptor if it doesn't hold any.
	 * @return Underlying file descriptor
	 */
	int release();

	/**
	 * @brief Close the file descriptor.
	 * @note If it doesn't hold any descriptor, no action is performed.
	 */
	void close() const noexcept;

private:
	constexpr static int INVALID_FILE_DESCRIPTOR = -1;
	int m_fileDescriptor = INVALID_FILE_DESCRIPTOR;
};

} // namespace ipxp::process::osquery
