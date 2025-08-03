#pragma once

#include <array>
#include <boost/container/static_vector.hpp>
#include <optional>
#include <span>

namespace ipxp
{

struct IDPContentExport {
	static constexpr std::size_t MAX_CONTENT_LENGTH = 100;
	using Content = boost::container::static_vector<std::byte, MAX_CONTENT_LENGTH>;

	DirectionalField<std::optional<Content>> directionalContent;	
};  

} // namespace ipxp

