/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief FieldManager manages registration and organization of record fields.
 *
 * FieldManager is responsible for:
 * - Creating FieldGroup instances for different logical groups
 * - Registering scalar and directional fields
 * - Keeping track of biflow and uniflow fields
 * - Providing access to field descriptors for introspection and validation
 *
 * It maintains internal bit indices for each field to efficiently check
 * presence in record instances.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "fieldDescriptor.hpp"
#include "fieldGenericValueGetter.hpp"
#include "fieldHandler.hpp"

#include <atomic>
#include <cstdint>
#include <string_view>
#include <utility>
#include <vector>

namespace ipxp::process {

class FieldGroup;

/**
 * @class FieldManager
 * @brief Central registry for record fields and their metadata.
 *
 * Provides methods to register fields, directional field pairs, and biflow pairs.
 * Offers access to field descriptors grouped by biflow/uniflow and direction.
 */
class FieldManager {
public:
	/**
	 * @brief Creates a FieldGroup for a given name.
	 * @param groupName Logical group name (e.g., "dns", "http").
	 * @return Newly created FieldGroup instance.
	 */
	[[nodiscard]] FieldGroup createFieldGroup(std::string_view groupName);

	/**
	 * @brief Returns all biflow fields.
	 * @return Reference to vector containing biflow field descriptors.
	 */
	[[nodiscard]] const std::vector<FieldDescriptor>& getBiflowFields() const noexcept;

	/**
	 * @brief Returns reverse biflow fields.
	 * @return Reference to vector containing reverse biflow field descriptors.
	 */
	[[nodiscard]] const std::vector<FieldDescriptor>& getReverseBiflowFields() const noexcept;

	/**
	 * @brief Returns uniflow forward fields.
	 * @return Reference to vector containing uniflow forward field descriptors.
	 */
	[[nodiscard]] const std::vector<FieldDescriptor>& getUniflowForwardFields() const noexcept;

	/**
	 * @brief Returns uniflow reverse fields.
	 * @return Reference to vector containing uniflow reverse field descriptors.
	 */
	[[nodiscard]] const std::vector<FieldDescriptor>& getUniflowReverseFields() const noexcept;

private:
	// registration of field can only be done by FieldGroup
	friend class FieldGroup;

	[[nodiscard]] FieldHandler registerField(
		std::string_view groupName,
		std::string_view fieldName,
		GenericValueGetter getter);

	[[nodiscard]] std::pair<FieldHandler, FieldHandler> registerDirectionalPairFields(
		std::string_view groupName,
		std::string_view forwardFieldName,
		std::string_view reverseFieldName,
		GenericValueGetter forwardGetter,
		GenericValueGetter reverseGetter);

	[[nodiscard]] std::pair<FieldHandler, FieldHandler> registerBiflowPairFields(
		std::string_view groupName,
		std::string_view aFieldName,
		std::string_view bFieldName,
		GenericValueGetter aGetter,
		GenericValueGetter bGetter);

	[[nodiscard]] std::size_t getNextBitIndex() noexcept
	{
		return m_fieldIndex.fetch_add(1, std::memory_order_relaxed);
	}

	void addField(
		std::vector<FieldDescriptor>& container,
		std::string_view group,
		std::string_view name,
		std::size_t bitIndex,
		GenericValueGetter getter);

	std::vector<FieldDescriptor> m_biflowFields;
	std::vector<FieldDescriptor> m_reverseBiflowFields;
	std::vector<FieldDescriptor> m_uniflowForwardFields;
	std::vector<FieldDescriptor> m_uniflowReverseFields;

	std::atomic<std::size_t> m_fieldIndex {0};
};

} // namespace ipxp::process
