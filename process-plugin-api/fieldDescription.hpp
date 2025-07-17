#pragma once

#include "fieldAccessor.hpp"
#include "fieldDirection.hpp"

#include <cstdint>
#include <string>
#include <variant>

namespace ipxp {

/**
 * @brief Describes a field in a flow record schema.
 *
 * Contains metadata necessary to identify and access a field value,
 * such as its group (e.g., "http", "tcp"), name (e.g., "IP_TTL"), direction
 * (forward, reverse, or indifferent), and value accessor.
 */
struct FieldDescription {
	/// Logical group to which this field belongs (e.g., "tls", "dns").
	std::string group;

	/// Name of the field (e.g., "SRC_PORT", "IP_TTL").
	std::string name;

	/// Direction of the field (Forward, Reverse, DirectionalIndifferent).
	FieldDirection direction;

	/// Value getter that allows access to the field's value in a record.
	GenericValueGetter getter;
};

} // namespace ipxp