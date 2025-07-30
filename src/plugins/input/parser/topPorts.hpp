/**
 * \file topPorts.hpp
 * \brief TopPorts class declaration implementing the most popular ports.
 * \author Damir Zainullin <zaidamilda@gmail.com>
 * \date 2024
 */
#pragma once

#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace ipxp {
/**
 * \brief Top ports counter.
 */
class TopPorts {
public:
	/**
	 * \brief Constructor.
	 * \param top_ports_count Number of the most popular ports to track.
	 */
	TopPorts(size_t top_ports_count) noexcept;

	/**
	 * \brief Increments number of times given tcp port has been seen.
	 * \param port Port to increment its frequency.
	 */
	void increment_tcp_frequency(uint16_t port) noexcept { m_tcp_port_frequencies[port]++; }

	/**
	 * \brief Increments number of times given udp port has been seen.
	 * \param port Port to increment its frequency.
	 */
	void increment_udp_frequency(uint16_t port) noexcept { m_udp_port_frequencies[port]++; }

	/**
	 * \brief Port frequency and protocol to which it belongs.
	 */
	struct PortStats {
		/**
		 * \brief Protocol type.
		 */
		enum class Protocol { TCP, UDP };

		uint16_t port; /**< Port number. */
		size_t frequency; /**< Number of times the port has been seen. */
		Protocol protocol; /**< Protocol to which the port belongs. */

		/**
		 * \brief Convert the port stats to string.
		 * \return String representation of the port stats.
		 */
		std::string to_string() const noexcept;
	};

	/**
	 * \brief Get the top ports.
	 * \return Vector of the most popular ports.
	 */
	std::vector<TopPorts::PortStats> get_top_ports() const noexcept;

private:
	std::array<std::size_t, std::numeric_limits<uint16_t>::max() + 1> m_tcp_port_frequencies {};
	std::array<std::size_t, std::numeric_limits<uint16_t>::max() + 1> m_udp_port_frequencies {};
	const size_t m_top_ports_count;
};

} // namespace ipxp
