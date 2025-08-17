#pragma once

#include <optional>
#include <span>
#include <cstdint>
#include <cstddef>
#include <arpa/inet.h>
#include <string>
#include <boost/container/static_vector.hpp>

namespace ipxp
{

/**
 * @brief Class represents DNS name
 */
class DNSName {
public:

    constexpr static
    std::optional<DNSName> createFrom(
        std::span<const std::byte> payload, 
        std::span<const std::byte> fullDNSpayload) noexcept;

    /**
     * @brief Converts DNS name to string
     * @param delimiter Delimiter to use between labels
     * @return Concatenated labels with delimiter
     */
    std::string toString(const char delimiter = '.') const noexcept;

    /**
     * @brief Get length of the DNS name
     * @return Length of DNS name excluding length of data pointed by DNS pointer
     * i.e after that count of bytes there is DNS question type field
     */
    constexpr std::size_t length() const noexcept;

    bool operator==(const DNSName& other) const noexcept;

private:
	constexpr static uint16_t MAX_LABEL_COUNT = 15;

    boost::container::static_vector<std::string_view, MAX_LABEL_COUNT> m_labels;
    size_t m_length{0};
    bool m_isPointer {false};
};


} // namespace ipxp
