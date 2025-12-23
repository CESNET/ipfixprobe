/**
 * @file
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @brief This file defines the FileDescriptor base classed used as wrapper for UNIX file
 * descriptors that manage its lifetime
 *
 * @copyright Copyright (c) 2024 CESNET, z.s.p.o.
 */

#include "fileDescriptor.hpp"

namespace ipxp::process {

FileDescriptor::operator bool() const noexcept
{
	return hasValue();
};

bool FileDescriptor::hasValue() const noexcept
{
	return m_fileDescriptor >= 0;
};

FileDescriptor::operator int() const noexcept
{
	return get();
};

int FileDescriptor::get() const noexcept
{
	return m_fileDescriptor;
};

int FileDescriptor::release()
{
	const auto originalValue = m_fileDescriptor;
	m_fileDescriptor = INVALID_FILE_DESCRIPTOR;
	return originalValue;
}

void FileDescriptor::close() const noexcept
{
	if (m_fileDescriptor != INVALID_FILE_DESCRIPTOR) {
		::close(m_fileDescriptor);
	}
}

FileDescriptor::FileDescriptor(const int fileDescriptor) noexcept
	: m_fileDescriptor(fileDescriptor)
{
}

FileDescriptor::FileDescriptor() noexcept
	: m_fileDescriptor(INVALID_FILE_DESCRIPTOR)
{
}

FileDescriptor::FileDescriptor(FileDescriptor&& other) noexcept
{
	std::swap(m_fileDescriptor, other.m_fileDescriptor);
}

FileDescriptor& FileDescriptor::operator=(FileDescriptor&& other) noexcept
{
	if (this != &other) {
		close();
		std::swap(m_fileDescriptor, other.m_fileDescriptor);
	}

	return *this;
}

FileDescriptor::~FileDescriptor() noexcept
{
	close();
}

} // namespace ipxp::process
