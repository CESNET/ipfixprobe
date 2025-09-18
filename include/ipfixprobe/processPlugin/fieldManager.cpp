/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Implementation of FieldManager methods for registering and accessing fields.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "fieldManager.hpp"
#include "fieldSchema.hpp"

namespace ipxp {

static FieldInfo makeFieldInfo(
	std::string_view group,
	std::string_view name,
	std::size_t bitIndex,
	GenericValueGetter getter)
{
	return {
		.group = std::string(group),
		.name = std::string(name),
		.bitIndex = bitIndex,
		.getter = std::move(getter),
	};
}

[[nodiscard]] FieldSchema FieldManager::createFieldSchema(std::string_view groupName)
{
	return FieldSchema(groupName, *this);
}

const std::vector<FieldDescriptor>& FieldManager::getBiflowFields() const
{
	return m_biflowFields;
}

const std::vector<FieldDescriptor>& FieldManager::getReverseBiflowFields() const
{
	return m_reverseBiflowFields;
}

const std::vector<FieldDescriptor>& FieldManager::getUniflowForwardFields() const
{
	return m_uniflowForwardFields;
}

const std::vector<FieldDescriptor>& FieldManager::getUniflowReverseFields() const
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

	const FieldInfo fieldInfo = makeFieldInfo(groupName, fieldName, bitIndex, getter);

	m_biflowFields.emplace_back(FieldDescriptor(fieldInfo));
	m_reverseBiflowFields.emplace_back(FieldDescriptor(fieldInfo));
	m_uniflowForwardFields.emplace_back(FieldDescriptor(fieldInfo));
	m_uniflowReverseFields.emplace_back(FieldDescriptor(fieldInfo));

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

	const FieldInfo forwardFieldInfoInBiflow
		= makeFieldInfo(groupName, forwardFieldName, forwardBitIndex, forwardGetter);

	const FieldInfo reverseFieldInfoInBiflow
		= makeFieldInfo(groupName, reverseFieldName, reverseBitIndex, reverseGetter);

	m_biflowFields.emplace_back(FieldDescriptor(forwardFieldInfoInBiflow));
	m_biflowFields.emplace_back(FieldDescriptor(reverseFieldInfoInBiflow));

	const FieldInfo forwardFieldInfoInReverseBiflow
		= makeFieldInfo(groupName, forwardFieldName, reverseBitIndex, forwardGetter);

	const FieldInfo reverseFieldInfoInReverseBiflow
		= makeFieldInfo(groupName, reverseFieldName, forwardBitIndex, reverseGetter);

	m_reverseBiflowFields.emplace_back(FieldDescriptor(forwardFieldInfoInReverseBiflow));
	m_reverseBiflowFields.emplace_back(FieldDescriptor(reverseFieldInfoInReverseBiflow));

	const FieldInfo forwardFieldInUniflow
		= makeFieldInfo(groupName, forwardFieldName, forwardBitIndex, forwardGetter);

	const FieldInfo reverseFieldInUniflow
		= makeFieldInfo(groupName, forwardFieldName, reverseBitIndex, reverseGetter);

	m_uniflowForwardFields.emplace_back(FieldDescriptor(forwardFieldInUniflow));
	m_uniflowReverseFields.emplace_back(FieldDescriptor(reverseFieldInUniflow));

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

	const FieldInfo aFieldInfoInBiflow = makeFieldInfo(groupName, aFieldName, aBitIndex, aGetter);

	const FieldInfo bFieldInfoInBiflow = makeFieldInfo(groupName, bFieldName, bBitIndex, bGetter);

	m_biflowFields.emplace_back(FieldDescriptor(aFieldInfoInBiflow));
	m_biflowFields.emplace_back(FieldDescriptor(bFieldInfoInBiflow));

	const FieldInfo aFieldInfoInReverseBiflow
		= makeFieldInfo(groupName, aFieldName, bBitIndex, aGetter);

	const FieldInfo bFieldInfoInReverseBiflow
		= makeFieldInfo(groupName, bFieldName, aBitIndex, bGetter);

	m_reverseBiflowFields.emplace_back(FieldDescriptor(aFieldInfoInReverseBiflow));
	m_reverseBiflowFields.emplace_back(FieldDescriptor(bFieldInfoInReverseBiflow));

	const FieldInfo aFieldInForwardUniflow
		= makeFieldInfo(groupName, aFieldName, aBitIndex, aGetter);

	const FieldInfo bFieldInForwardUniflow
		= makeFieldInfo(groupName, bFieldName, bBitIndex, bGetter);

	m_uniflowForwardFields.emplace_back(FieldDescriptor(aFieldInForwardUniflow));
	m_uniflowForwardFields.emplace_back(FieldDescriptor(bFieldInForwardUniflow));

	const FieldInfo aFieldInReverseUniflow
		= makeFieldInfo(groupName, aFieldName, bBitIndex, aGetter);

	const FieldInfo bFieldInReverseUniflow
		= makeFieldInfo(groupName, bFieldName, aBitIndex, bGetter);

	m_uniflowReverseFields.emplace_back(FieldDescriptor(aFieldInReverseUniflow));
	m_uniflowReverseFields.emplace_back(FieldDescriptor(bFieldInReverseUniflow));

	return {aFieldHandler, bFieldHandler};
}

} // namespace ipxp
