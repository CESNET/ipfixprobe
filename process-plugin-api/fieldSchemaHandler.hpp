#pragma once

#include "fieldHandler.hpp"

#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>

namespace ipxp {

/**
 * @brief Provides access to field handlers by name.
 *
 * FieldSchemaHandler is a utility class that maps string field names
 * to their associated FieldHandler objects. It is typically created
 * and managed by a FieldManager and used by plugins or builders
 * to query availability and manipulate flow fields.
 */
class FieldSchemaHandler {
public:
	/**
	 * @brief Returns the FieldHandler for a given field name.
	 *
	 * @param name Name of the field.
	 * @return FieldHandler associated with the field.
	 * @throws std::runtime_error if the field name is not registered.
	 */
	FieldHandler getFieldHandler(std::string_view name) const
	{
		auto it = m_fieldHandlers.find(std::string(name));
		if (it != m_fieldHandlers.end()) {
			return it->second;
		}

		throw std::runtime_error("FieldHandler not found for name: " + std::string(name));
	}

private:
	friend class FieldManager;

	/// Constructor is private and accessible only to FieldManager.
	FieldSchemaHandler() = default;

	/**
	 * @brief Registers a field handler under a given field name.
	 *
	 * @param fieldName Name of the field.
	 * @param fieldHandler Reference to the corresponding FieldHandler.
	 */
	void registerField(std::string_view fieldName, FieldHandler& fieldHandler)
	{
		m_fieldHandlers[std::string(fieldName)] = fieldHandler;
	}

	std::unordered_map<std::string, FieldHandler> m_fieldHandlers;
};

} // namespace ipxp