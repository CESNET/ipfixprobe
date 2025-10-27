/**
 * @file
 * @brief Range reader base class.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

namespace ipxp {

/**
 * @class RangeReader
 * @brief Base class for range readers.
 *
 * Provides common functionality for range readers, including tracking parsing state.
 */
class RangeReader {
public:
	constexpr bool parsedSuccessfully() const noexcept { return m_state == State::SUCCESS; }

protected:
	constexpr void setSuccess() noexcept { m_state = State::SUCCESS; }

private:
	enum class State { SUCCESS, FAILURE };

	State m_state {State::FAILURE};
};

} // namespace ipxp
