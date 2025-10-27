/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Implementation of FieldManager methods for registering and accessing fields.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "fieldManager.hpp"

#include "fieldGroup.hpp"

namespace ipxp::process {

void FieldManager::addField(
	std::vector<FieldDescriptor>& container,
	std::string_view group,
	std::string_view name,
	std::size_t bitIndex,
	GenericValueGetter getter)
{
	container.emplace_back(FieldDescriptor(
		FieldInfo {
			.group = std::string(group),
			.name = std::string(name),
			.bitIndex = bitIndex,
			.getter = std::move(getter),
		}));
}

[[nodiscard]] FieldGroup FieldManager::createFieldGroup(std::string_view groupName)
{
	return FieldGroup(groupName, *this);
}

const std::vector<FieldDescriptor>& FieldManager::getBiflowFields() const noexcept
{
	return m_biflowFields;
}

const std::vector<FieldDescriptor>& FieldManager::getReverseBiflowFields() const noexcept
{
	return m_reverseBiflowFields;
}

const std::vector<FieldDescriptor>& FieldManager::getUniflowForwardFields() const noexcept
{
	return m_uniflowForwardFields;
}

const std::vector<FieldDescriptor>& FieldManager::getUniflowReverseFields() const noexcept
{
	return m_uniflowReverseFields;
}

[[nodiscard]] FieldHandler FieldManager::registerField(
	std::string_view groupName,
	std::string_view fieldName,
	GenericValueGetter getter)
{
	const auto bitIndex = getNextBitIndex();
	const FieldHandler fieldHandler(bitIndex);

	// biflow
	addField(m_biflowFields, groupName, fieldName, bitIndex, getter);

	// reverse biflow
	addField(m_reverseBiflowFields, groupName, fieldName, bitIndex, getter);

	// forward uniflow
	addField(m_uniflowForwardFields, groupName, fieldName, bitIndex, getter);

	// reverse uniflow
	addField(m_uniflowReverseFields, groupName, fieldName, bitIndex, getter);

	return fieldHandler;
}

[[nodiscard]] std::pair<FieldHandler, FieldHandler> FieldManager::registerDirectionalPairFields(
	std::string_view groupName,
	std::string_view forwardFieldName,
	std::string_view reverseFieldName,
	GenericValueGetter forwardGetter,
	GenericValueGetter reverseGetter)
{
	const auto forwardBitIndex = getNextBitIndex();
	const auto reverseBitIndex = getNextBitIndex();

	const FieldHandler forwardFieldHandler(forwardBitIndex);
	const FieldHandler reverseFieldHandler(reverseBitIndex);

	// biflow
	addField(m_biflowFields, groupName, forwardFieldName, forwardBitIndex, forwardGetter);
	addField(m_biflowFields, groupName, reverseFieldName, reverseBitIndex, reverseGetter);

	// reverse biflow
	addField(m_reverseBiflowFields, groupName, forwardFieldName, reverseBitIndex, reverseGetter);
	addField(m_reverseBiflowFields, groupName, reverseFieldName, forwardBitIndex, forwardGetter);

	// forward uniflow
	addField(m_uniflowForwardFields, groupName, forwardFieldName, forwardBitIndex, forwardGetter);

	// reverse uniflow
	addField(m_uniflowReverseFields, groupName, forwardFieldName, reverseBitIndex, reverseGetter);

	return {forwardFieldHandler, reverseFieldHandler};
}

[[nodiscard]] std::pair<FieldHandler, FieldHandler> FieldManager::registerBiflowPairFields(
	std::string_view groupName,
	std::string_view aFieldName,
	std::string_view bFieldName,
	GenericValueGetter aGetter,
	GenericValueGetter bGetter)
{
	const std::size_t aBitIndex = getNextBitIndex();
	const std::size_t bBitIndex = getNextBitIndex();

	const FieldHandler aFieldHandler(aBitIndex);
	const FieldHandler bFieldHandler(bBitIndex);

	// biflow
	addField(m_biflowFields, groupName, aFieldName, aBitIndex, aGetter);
	addField(m_biflowFields, groupName, bFieldName, bBitIndex, bGetter);

	// reverse biflow
	addField(m_reverseBiflowFields, groupName, aFieldName, bBitIndex, bGetter);
	addField(m_reverseBiflowFields, groupName, bFieldName, aBitIndex, aGetter);

	// forward uniflow
	addField(m_uniflowForwardFields, groupName, aFieldName, aBitIndex, aGetter);
	addField(m_uniflowForwardFields, groupName, bFieldName, bBitIndex, bGetter);

	// reverse uniflow
	addField(m_uniflowReverseFields, groupName, aFieldName, bBitIndex, bGetter);
	addField(m_uniflowReverseFields, groupName, bFieldName, aBitIndex, aGetter);

	return {aFieldHandler, bFieldHandler};
}

} // namespace ipxp::process
