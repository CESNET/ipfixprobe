#pragma once

#include <cstddef>

namespace ipxp {

enum class WireguardFields : std::size_t {
	WG_CONF_LEVEL = 0,
	WG_SRC_PEER,
	WG_DST_PEER,
	FIELDS_SIZE,
};

} // namespace ipxp
