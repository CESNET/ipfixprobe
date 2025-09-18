/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Defines FieldInfo structure for storing field metadata and value accessors.
 *
 * FieldInfo encapsulates basic metadata about a field, including:
 * - The logical group the field belongs to (e.g., "dns", "http")
 * - The field's name
 * - Bit index for presence checking in FlowRecord
 * - GenericValueGetter for accessing the field's value
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "fieldGenericValueGetter.hpp"

#include <cstdint>
#include <string>

namespace ipxp {

/**
 * @struct FieldInfo
 * @brief Stores metadata and access information for a single field.
 *
 * Used internally by FieldDescriptor and FieldManager to provide
 * read-only access to field properties and values.
 */
struct FieldInfo {
	std::string group; /**< Logical group of the field (e.g., "dns", "http") */
	std::string name; /**< Name of the field */
	std::size_t bitIndex; /**< Bit index for presence checking in FlowRecord */
	GenericValueGetter getter; /**< Generic value accessor for the field */
};

} // namespace ipxp