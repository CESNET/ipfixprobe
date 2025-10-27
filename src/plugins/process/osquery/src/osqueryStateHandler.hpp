/**
 * @file
 * @brief Query state handler that displays if read was successful or not.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>

namespace ipxp::process::osquery {

/**
 * \brief Additional structure for handling osquery states.
 */
struct OSQueryStateHandler {
	enum StateFlags {
		FATAL_ERROR = 0b00000001, // 1;  Fatal error, cannot be fixed
		OPEN_ERROR = 0b00000010, // 2;  Failed to open osquery FD
		READ_ERROR = 0b00000100, // 4;  Error while reading
		READ_SUCCESS = 0b00001000, // 8;  Data read successfully
		OPEN = 0b00010000 // 16; FD open
	};

	bool isErrorState() const noexcept { return (state & (FATAL_ERROR | OPEN_ERROR | READ_ERROR)); }

	void setOpen() noexcept { state |= OPEN; }

	void setClosed() noexcept { state &= ~OPEN; }

	bool isOpen() const noexcept { return state & OPEN; }

	void setFatalError() noexcept { state |= FATAL_ERROR; }

	bool isFatalError() const noexcept { return state & FATAL_ERROR; }

	void setOpenError() noexcept { state |= OPEN_ERROR; }

	bool isOpenError() const noexcept { return state & OPEN_ERROR; }

	void setReadError() noexcept { state |= READ_ERROR; }

	bool isReadError() const noexcept { return state & READ_ERROR; }

	void setReadSuccess() noexcept { state |= READ_SUCCESS; }

	bool isReadSuccess() const noexcept { return state & READ_SUCCESS; }

	/**
	 * Reset the \p OSQUERY_STATE. Fatal and open fd errors will not be reset.
	 */
	void refresh() noexcept { state &= FATAL_ERROR | OPEN_ERROR; }

	/**
	 * Reset the \p OSQUERY_STATE. Fatal and open fd errors will be reset.
	 */
	void reset() noexcept { state = 0; }

private:
	uint8_t state {0};
};

} // namespace ipxp::process::osquery
