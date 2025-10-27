/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief FieldManager manages registration and organization of FlowRecord fields.
 *
 * FieldManager is responsible for:
 * - Creating FieldGroup instances for different logical groups
 * - Registering scalar and directional fields
 * - Keeping track of biflow and uniflow fields
 * - Providing access to field descriptors for introspection and validation
 *
 * It maintains internal bit indices for each field to efficiently check
 * presence in FlowRecord instances.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "fieldDescriptor.hpp"
#include "fieldGenericValueGetter.hpp"
#include "fieldHandler.hpp"
#include "../api.hpp"

#include <atomic>
#include <cstdint>
#include <string_view>
#include <utility>
#include <vector>

namespace ipxp {

class FieldGroup;

/**
 * @class FieldManager
 * @brief Central registry for FlowRecord fields and their metadata.
 *
 * Provides methods to register fields, directional field pairs, and biflow pairs.
 * Offers access to field descriptors grouped by biflow/uniflow and direction.
 */
class IPXP_API FieldManager {
public:
	/**
	 * @brief Creates a FieldGroup for a given name.
	 * @param groupName Logical group name (e.g., "dns", "http").
	 * @return Newly created FieldGroup instance.
	 */
	[[nodiscard]] FieldGroup createFieldGroup(std::string_view groupName);

	/** @brief Returns all biflow fields. */
	const std::vector<FieldDescriptor>& getBiflowFields() const;

	/** @brief Returns reverse biflow fields. */
	const std::vector<FieldDescriptor>& getReverseBiflowFields() const;

	/** @brief Returns uniflow forward fields. */
	const std::vector<FieldDescriptor>& getUniflowForwardFields() const;

	/** @brief Returns uniflow reverse fields. */
	const std::vector<FieldDescriptor>& getUniflowReverseFields() const;

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

	[[nodiscard]] std::size_t getNextBitIndex() noexcept { return m_fieldIndex++; }

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

	std::size_t m_fieldIndex = 0;
};

} // namespace ipxp
