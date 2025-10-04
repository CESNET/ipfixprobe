/**
 * @file
 * @brief Parsing state of range reader.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

namespace ipxp {

/**
 * @struct ParsingState
 * @brief Represents the final state of parsing in range reader.
 */
struct ParsingState {
	enum class State { SUCCESS, FAILURE };
	State state {State::FAILURE};
};

} // namespace ipxp
