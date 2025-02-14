/**
 * \file topPorts.cpp
 * \brief TopPorts class implementation.
 * \author Damir Zainullin <zaidamilda@gmail.com>
 * \date 2024
 */

#include "topPorts.hpp"

#include <functional>
#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <vector>
#include <string>

namespace ipxp {

TopPorts::TopPorts(size_t top_ports_count) noexcept
: m_top_ports_count(top_ports_count)
{
}

void TopPorts::increment_tcp_frequency(uint16_t port) noexcept
{
    m_tcp_port_frequencies[port]++;
}

void TopPorts::increment_udp_frequency(uint16_t port) noexcept
{
    m_udp_port_frequencies[port]++;
}

std::string TopPorts::PortStats::to_string() const noexcept
{
    return std::to_string(port) + "[" +
        (protocol == Protocol::TCP ? "TCP" : "UDP") + "] - " + std::to_string(frequency);
}

std::vector<TopPorts::PortStats> TopPorts::get_top_ports() const noexcept
{
    std::vector<PortStats> port_buffer(10);
    size_t ports_inserted = 0;

    auto callback = [&, port = uint16_t{0}](size_t frequency, PortStats::Protocol protocol) mutable {
        auto port_pos = std::lower_bound(port_buffer.begin(), port_buffer.end(), frequency,
        [](const PortStats& port_frequency, size_t count) {
                return port_frequency.frequency >= count;
        });

        if (port_pos != port_buffer.end()) {
            std::copy_backward(port_pos, std::prev(port_buffer.end()), port_buffer.end());
            *port_pos = PortStats{port, frequency, protocol};
            ports_inserted = std::min<size_t>(m_top_ports_count, ports_inserted + 1);
        }
        port++;
    };

    std::for_each(m_tcp_port_frequencies.begin(), m_tcp_port_frequencies.end(), [callback](size_t frequency) mutable {
        callback(frequency, PortStats::Protocol::TCP);
    });
    std::for_each(m_udp_port_frequencies.begin(), m_udp_port_frequencies.end(), [callback](size_t frequency) mutable{
         callback(frequency, PortStats::Protocol::UDP);
     });

    port_buffer.resize(std::min(m_top_ports_count, ports_inserted));
    return port_buffer;
}

} // namespace ipxp
