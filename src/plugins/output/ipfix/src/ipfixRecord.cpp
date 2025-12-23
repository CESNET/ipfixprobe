#include "ipfixRecord.hpp"

#include "ipfixBasicList.hpp"

#include <ranges>

namespace ipxp::output::ipfix {

std::size_t getLengthOfVectorField(
	const process::FieldDescriptor* const fieldDescriptor,
	const FlowRecord& flowRecord) noexcept
{
	if (!fieldDescriptor->isInRecord(flowRecord)) {
		return IPFIXBasicList().getSize();
	}

	// IPFIXBasicList list {std::span<const float>()}; // Placeholder

	const void* pluginExportData = flowRecord.getPluginContext(fieldDescriptor->getBitIndex());
	const auto& variant = std::get<process::VectorValueGetter>(fieldDescriptor->getValueGetter());
	const auto visitor = [&](const auto& accessor) {
		// using AccessorT = std::decay_t<decltype(accessor)>;
		const auto& values = accessor(pluginExportData);
		return IPFIXBasicList(values).getSize();
	};
	return std::visit(visitor, variant);
}

template<typename T>
T getEmptyValue() noexcept
{
	if constexpr (std::is_same_v<T, ipxp::IPAddressVariant>) {
		return ipxp::IPAddressVariant {static_cast<uint32_t>(0)};
	} else if constexpr (
		std::is_same_v<T, std::string_view> || std::is_same_v<T, std::string>
		|| std::is_same_v<T, amon::types::MACAddress> || std::is_same_v<T, amon::types::IPv4>
		|| std::is_same_v<T, amon::types::IPv6> || std::is_same_v<T, amon::types::Timestamp>
		|| std::is_same_v<T, ipxp::IPAddressVariant>) {
		return T {};
	} else {
		return T {0};
	}
}

void storeEmptyScalar(
	const process::FieldDescriptor& field,
	const process::ScalarValueGetter& variant,
	utils::ByteWriter& outputWriter) noexcept
{
	const auto visitor = [&](const auto& accessor) {
		const auto emptyScalar = getEmptyValue<decltype(accessor(std::declval<const void*>()))>();
		outputWriter.write(emptyScalar);
	};
	std::visit(visitor, variant);
}

void storeEmptyList(
	const process::FieldDescriptor& field,
	const process::VectorValueGetter& variant,
	utils::ByteWriter& outputWriter) noexcept
{
	IPFIXBasicList list;
	list.writeTo(outputWriter);
}

void storeEmptyField(
	const process::FieldDescriptor& fieldDescriptor,
	const FlowRecord& flowRecord,
	utils::ByteWriter& outputWriter) noexcept
{
	const auto& getter = fieldDescriptor.getValueGetter();
	std::visit(
		[&](const auto& variant) {
			using GetterT = std::decay_t<decltype(variant)>;
			if constexpr (std::is_same_v<GetterT, process::ScalarValueGetter>) {
				storeEmptyScalar(fieldDescriptor, variant, outputWriter);
			} else if constexpr (std::is_same_v<GetterT, process::VectorValueGetter>) {
				storeEmptyList(fieldDescriptor, variant, outputWriter);
			}
		},
		getter);
}

template<typename T>
void storeScalar(
	const process::FieldDescriptor& field,
	const process::ScalarAccessor<T>& accessor,
	const void* data,
	utils::ByteWriter& outputWriter)
{
	outputWriter.write(utils::byteSwap(accessor(data)));
}

void storeScalarField(
	const process::FieldDescriptor& field,
	const process::ScalarValueGetter& variant,
	const void* data,
	utils::ByteWriter& outputWriter)
{
	const auto visitor
		= [&](const auto& accessor) { storeScalar(field, accessor, data, outputWriter); };
	std::visit(visitor, variant);
}

template<typename T>
void storeVector(
	const process::FieldDescriptor& field,
	const process::VectorAccessor<T>& accessor,
	const void* data,
	utils::ByteWriter& outputWriter)
{
	const auto& values = accessor(data);
	IPFIXBasicList list(values);
	list.writeTo(outputWriter);
}

void storeVectorField(
	const process::FieldDescriptor& field,
	const process::VectorValueGetter& variant,
	const void* data,
	utils::ByteWriter& outputWriter)
{
	const auto visitor
		= [&](const auto& accessor) { storeVector(field, accessor, data, outputWriter); };
	std::visit(visitor, variant);
}

IPFIXRecord::IPFIXRecord(
	const ProtocolFieldMap& protocolFields,
	const FlowRecord& flowRecord,
	const IPFIXTemplate& ipfixTemplate) noexcept
	: m_protocolFields(protocolFields)
	, m_flowRecord(flowRecord)
	, m_ipfixTemplate(ipfixTemplate)
	, m_size(calculateSize())
{
}

static void forEachFieldDescriptor(
	const IPFIXTemplate& ipfixTemplate,
	const ProtocolFieldMap& protocolFields,
	auto&& callable) noexcept
{
	for (const process::FieldDescriptor* const fieldDescriptor :
		 ipfixTemplate.requiredProtocolIndices
			 | std::views::transform([&](const std::size_t protocolIndex) {
				   return protocolFields.getFieldsOnIndex(protocolIndex);
			   })
			 | std::views::join) {
		callable(fieldDescriptor);
	}
}

std::size_t IPFIXRecord::calculateSize() noexcept
{
	std::size_t variableLengthSize = 0;
	forEachFieldDescriptor(
		m_ipfixTemplate,
		m_protocolFields,
		[&](const process::FieldDescriptor* const fieldDescriptor) {
			const auto& getter = fieldDescriptor->getValueGetter();
			if (!std::holds_alternative<process::VectorValueGetter>(getter)) {
				return;
			}
			variableLengthSize += getLengthOfVectorField(fieldDescriptor, m_flowRecord);
		});
	return variableLengthSize + m_ipfixTemplate.staticSize;
}

/*void IPFIXRecord::forEachFieldView(auto&& callable) const noexcept
{
	forEachFieldDescriptor(
		m_ipfixTemplate,
		m_protocolFields,
		[&](const process::FieldDescriptor* const fieldDescriptor) {
			callable(getFieldView(fieldDescriptor));
		});
}*/

/*std::span<const std::byte>
IPFIXRecord::getFieldView(const process::FieldDescriptor* const fieldDescriptor) noexcept
{
	if (!fieldDescriptor->isInRecord(m_flowRecord)) {
		saveEmptyFieldView(fieldDescriptor, m_flowRecord, m_serializationBuffer);
		return std::span<const std::byte>(
			m_serializationBuffer.data(),
			m_serializationBuffer.size());
	}

	const void* pluginExportData =
m_flowRecord.getPluginContext(fieldDescriptor->getBitIndex()); const auto& getter =
fieldDescriptor->getValueGetter(); std::visit(
		[&](const auto& variant) {
			using GetterT = std::decay_t<decltype(variant)>;
			if constexpr (std::is_same_v<GetterT, ScalarValueGetter>) {
				saveScalarFieldView(
					fieldDescriptor,
					variant,
					pluginExportData,
					m_serializationBuffer);
			} else if constexpr (std::is_same_v<GetterT, VectorValueGetter>) {
				saveVectorFieldView(
					fieldDescriptor,
					variant,
					pluginExportData,
					m_serializationBuffer);
			}
		},
		getter);
	return std::span<const std::byte>(m_serializationBuffer.data(),
m_serializationBuffer.size());
}*/

void IPFIXRecord::writeTo(utils::ByteWriter& outputWriter) const noexcept
{
	forEachFieldDescriptor(
		m_ipfixTemplate,
		m_protocolFields,
		[&](const process::FieldDescriptor* const fieldDescriptor) {
			if (!fieldDescriptor->isInRecord(m_flowRecord)) {
				storeEmptyField(*fieldDescriptor, m_flowRecord, outputWriter);
				return;
			}

			const void* pluginExportData
				= m_flowRecord.getPluginContext(fieldDescriptor->getBitIndex());
			const auto& getter = fieldDescriptor->getValueGetter();
			std::visit(
				[&](const auto& variant) {
					using GetterT = std::decay_t<decltype(variant)>;
					if constexpr (std::is_same_v<GetterT, process::ScalarValueGetter>) {
						storeScalarField(*fieldDescriptor, variant, pluginExportData, outputWriter);
					} else if constexpr (std::is_same_v<GetterT, process::VectorValueGetter>) {
						storeVectorField(*fieldDescriptor, variant, pluginExportData, outputWriter);
					}
				},
				getter);
		});
}

} // namespace ipxp::output::ipfix