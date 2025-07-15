/**
 * @file
 * @brief Declarations for field management
 *
 * Provides classes for schema registration and mapping between field names
 * and their internal field handlers.
 */

#pragma once

#include "fieldHandler.hpp"
#include "fieldSchema.hpp"
#include "fieldSchemaHandler.hpp"
#include "outputField.hpp"

#include <atomic>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

/**
 * @brief Manages field handlers and schema registrations.
 *
 * Plugins use this to register their field schemas during construction.
 */
class FieldManager {
public:
	/// Default constructor.
	FieldManager() = default;

	FieldSchemaHandler registerSchema(const FieldSchema& schema)
	{
		// TODO - validate schema (duplication, etc.)

		FieldSchemaHandler schemaHandler;
		for (const auto& field : schema.getFields()) {
			FieldHandler fieldHandler(m_fieldIndex);
			schemaHandler.registerField(field.name, fieldHandler);
			m_fields.emplace_back(OutputField(field, m_fieldIndex));

			m_fieldIndex++;
		}

		m_schemas.emplace_back(schema);
		return schemaHandler;
	}

	std::span<OutputField> getFields() { return m_fields; }

private:
	std::vector<OutputField> m_fields;
	std::vector<FieldSchema> m_schemas;
	std::atomic<std::size_t> m_fieldIndex = 0;
};
