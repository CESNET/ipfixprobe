#pragma once

#include "ipfixRecordWriter.hpp"

namespace ipxp::output::ipfix {

/*std::size_t getLengthOfVectorField(
	const process::FieldDescriptor* const fieldDescriptor,
	const FlowRecord& flowRecord) noexcept
{
	if (!fieldDescriptor->isInRecord(flowRecord)) {
		return IPFIXBasicList().getSize();
	}

	const void* pluginExportData = flowRecord.getPluginContext(fieldDescriptor->getBitIndex());
	const auto& variant = std::get<process::VectorValueGetter>(fieldDescriptor->getValueGetter());
	const auto visitor = [&](const auto& accessor) {
		// using AccessorT = std::decay_t<decltype(accessor)>;
		const auto& values = accessor(pluginExportData);
		return IPFIXBasicList(values).getSize();
	};
	return std::visit(visitor, variant);
}*/

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

bool storeEmptyScalar(
	const process::FieldDescriptor& field,
	const process::ScalarValueGetter& variant,
	utils::ByteWriter& outputWriter) noexcept
{
	const auto visitor = [&](const auto& accessor) {
		const auto emptyScalar = getEmptyValue<decltype(accessor(std::declval<const void*>()))>();
		return outputWriter.write(emptyScalar);
	};
	return std::visit(visitor, variant);
}

bool storeEmptyList(
	const process::FieldDescriptor& field,
	const process::VectorValueGetter& variant,
	utils::ByteWriter& outputWriter) noexcept
{
	IPFIXBasicList list;
	return list.writeTo(outputWriter);
}

bool storeEmptyField(
	const process::FieldDescriptor& fieldDescriptor,
	const FlowRecord& flowRecord,
	utils::ByteWriter& outputWriter) noexcept
{
	const auto& getter = fieldDescriptor.getValueGetter();
	return std::visit(
		[&](const auto& variant) {
			using GetterT = std::decay_t<decltype(variant)>;
			if constexpr (std::is_same_v<GetterT, process::ScalarValueGetter>) {
				return storeEmptyScalar(fieldDescriptor, variant, outputWriter);
			} else if constexpr (std::is_same_v<GetterT, process::VectorValueGetter>) {
				return storeEmptyList(fieldDescriptor, variant, outputWriter);
			}
		},
		getter);
}

template<typename T>
bool storeScalar(
	const process::FieldDescriptor& field,
	const process::ScalarAccessor<T>& accessor,
	const void* data,
	utils::ByteWriter& outputWriter)
{
	return outputWriter.write(utils::byteSwap(accessor(data)));
}

bool storeScalarField(
	const process::FieldDescriptor& field,
	const process::ScalarValueGetter& variant,
	const void* data,
	utils::ByteWriter& outputWriter)
{
	const auto visitor
		= [&](const auto& accessor) { return storeScalar(field, accessor, data, outputWriter); };
	return std::visit(visitor, variant);
}

template<typename T>
bool storeVector(
	const process::FieldDescriptor& field,
	const process::VectorAccessor<T>& accessor,
	const void* data,
	utils::ByteWriter& outputWriter)
{
	const auto& values = accessor(data);
	IPFIXBasicList list(values);
	return list.writeTo(outputWriter);
}

bool storeVectorField(
	const process::FieldDescriptor& field,
	const process::VectorValueGetter& variant,
	const void* data,
	utils::ByteWriter& outputWriter)
{
	const auto visitor
		= [&](const auto& accessor) { return storeVector(field, accessor, data, outputWriter); };
	return std::visit(visitor, variant);
}

static bool forEachFieldDescriptor(
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
		if (!callable(fieldDescriptor)) {
			return false;
		}
	}
	return true;
}

bool IPFIXRecordWriter::writeRecordTo(
	const IPFIXRecord& record,
	utils::ByteWriter& outputWriter) noexcept
{
	return forEachFieldDescriptor(
		record.ipfixTemplate,
		record.protocolFields,
		[&](const process::FieldDescriptor* const fieldDescriptor) {
			if (!fieldDescriptor->isInRecord(record.flowRecord)) {
				return storeEmptyField(*fieldDescriptor, record.flowRecord, outputWriter);
			}

			const void* pluginExportData
				= record.flowRecord.getPluginContext(fieldDescriptor->getBitIndex());
			const auto& getter = fieldDescriptor->getValueGetter();
			return std::visit(
				[&](const auto& variant) {
					using GetterT = std::decay_t<decltype(variant)>;
					if constexpr (std::is_same_v<GetterT, process::ScalarValueGetter>) {
						return storeScalarField(
							*fieldDescriptor,
							variant,
							pluginExportData,
							outputWriter);
					} else if constexpr (std::is_same_v<GetterT, process::VectorValueGetter>) {
						return storeVectorField(
							*fieldDescriptor,
							variant,
							pluginExportData,
							outputWriter);
					}
				},
				getter);
		});
}

} // namespace ipxp::output::ipfix