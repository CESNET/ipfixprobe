/**
 * \file topPorts.cpp
 * \brief TopPorts class implementation.
 * \author Damir Zainullin <zaidamilda@gmail.com>
 * \date 2024
 */

#include "topPorts.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <limits>
#include <string>
#include <vector>

namespace ipxp {

TopPorts::TopPorts(size_t top_ports_count) noexcept
	: m_top_ports_count(top_ports_count)
{
}

std::string TopPorts::PortStats::to_string() const noexcept
{
	return std::to_string(port) + "[" + (protocol == Protocol::TCP ? "TCP" : "UDP") + "] - "
		+ std::to_string(frequency);
}

bool update_port_buffer(
	std::vector<TopPorts::PortStats>& port_buffer,
	TopPorts::PortStats port_stats) noexcept
{
	auto port_pos = std::lower_bound(
		port_buffer.begin(),
		port_buffer.end(),
		port_stats.frequency,
		[](const TopPorts::PortStats& port_frequency, size_t count) {
			return port_frequency.frequency >= count;
		});

	if (port_pos != port_buffer.end()) {
		std::copy_backward(port_pos, std::prev(port_buffer.end()), port_buffer.end());
		*port_pos = port_stats;
		return true;
	}
	return false;
};

std::vector<TopPorts::PortStats> TopPorts::get_top_ports() const noexcept
{
	std::vector<PortStats> port_buffer(m_top_ports_count);
	size_t ports_inserted = 0;

	std::for_each(
		m_tcp_port_frequencies.begin(),
		m_tcp_port_frequencies.end(),
		[&, port = uint16_t {0}](size_t frequency) mutable {
			ports_inserted
				+= update_port_buffer(port_buffer, {port++, frequency, PortStats::Protocol::TCP});
		});
	std::for_each(
		m_udp_port_frequencies.begin(),
		m_udp_port_frequencies.end(),
		[&, port = uint16_t {0}](size_t frequency) mutable {
			ports_inserted
				+= update_port_buffer(port_buffer, {port++, frequency, PortStats::Protocol::UDP});
		});

	port_buffer.resize(std::min(m_top_ports_count, ports_inserted));
	return port_buffer;
}

} // namespace ipxp
