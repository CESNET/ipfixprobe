/**
 * \file topPorts.hpp
 * \brief Template class implementing the most popular ports.
 * \author Damir Zainullin <zaidamilda@gmail.com>
 * \date 2024
 */
#pragma once

#include <array>
#include <cmath>
#include <cstdint>
#include <functional>
#include <limits>
#include <queue>
#include <unordered_map>
#include <unordered_set>

namespace ipxp {
/**
 * \brief Top ports counter.
 * \tparam TopPortsCount Number of the most popular ports to store.
 */
template<std::size_t TopPortsCount>
class TopPorts {
public:
    /**
     * \brief Insert a port into the top ports.
     * \param port Port to insert.
     */
    void insert(uint16_t port) noexcept
    {
        m_port_frequencies[port]++;

        if (m_ports_present.size() < TopPortsCount) {
            m_ports_present.insert(port);
            m_least_popuplar_top_port = find_least_popular_top_port();
            return;
        }

        if (auto it = m_ports_present.find(port); it == m_ports_present.end()
            && m_port_frequencies[port] > m_port_frequencies[m_least_popuplar_top_port]) {
            m_ports_present.erase(m_least_popuplar_top_port);
            m_least_popuplar_top_port = port;
            m_ports_present.insert(port);
        } else if (port == m_least_popuplar_top_port) {
            m_least_popuplar_top_port = find_least_popular_top_port();
        }
    }

    /**
     * \brief Get the top ports.
     * \return Pair of the top ports array and their count.
     */
    std::pair<std::array<std::pair<uint16_t, size_t>, TopPortsCount>, size_t>
    get_top_ports() const noexcept
    {
        std::array<std::pair<uint16_t, size_t>, TopPortsCount> res;
        std::transform(
            m_ports_present.begin(),
            m_ports_present.end(),
            res.begin(),
            [this](uint16_t port) { return std::make_pair(port, m_port_frequencies[port]); });
	std::sort(res.begin(), res.begin() + m_ports_present.size(), [] (const std::pair<uint16_t, size_t>& port1, const std::pair<uint16_t, size_t>& port2){ return port1.second > port2.second;});
        return {res, m_ports_present.size()};
    }

private:
    uint16_t find_least_popular_top_port() const noexcept
    {
        return *std::min_element(
            m_ports_present.begin(),
            m_ports_present.end(),
            [this](uint16_t port1, uint16_t port2) {
                return m_port_frequencies[port1] < m_port_frequencies[port2];
            });
    }

    std::array<std::size_t, 65536> m_port_frequencies {};
    uint16_t m_least_popuplar_top_port {0};
    std::unordered_set<uint16_t> m_ports_present;
};

} // namespace ipxp
