/**
 * @file
 * @brief Export data of idpcontent plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <array>
#include <optional>
#include <span>

#include <boost/container/static_vector.hpp>
#include <directionalField.hpp>

namespace ipxp::process::idpContent {

/**
 * @struct IDPContentContext
 * @brief Struct representing export of IDP content plugin.
 *
 * Contains payloads for both flow direction.
 */
struct IDPContentContext {
	static constexpr std::size_t MAX_CONTENT_LENGTH = 100;
	using Content = boost::container::static_vector<std::byte, MAX_CONTENT_LENGTH>;

	DirectionalField<std::optional<Content>> directionalContent;
};

} // namespace ipxp::process::idpContent
