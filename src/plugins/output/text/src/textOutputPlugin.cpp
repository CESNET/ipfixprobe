#include "textOutputPlugin.hpp"

namespace ipxp {

inline std::ostream& operator<<(std::ostream& os, std::byte b)
{
	os << "0x" << std::hex << std::uppercase << static_cast<int>(b);
	return os;
}

template<typename T>
static void
printScalar(const FieldDescriptor& field, const ScalarAccessor<T>& accessor, const void* data)
{
	std::cout << "[" << field.getGroup() << "] " << field.getName() << ": " << accessor(data)
			  << "\n";
}

template<typename T>
static void
printVector(const FieldDescriptor& field, const VectorAccessor<T>& accessor, const void* data)
{
	std::cout << "[" << field.getGroup() << "] " << field.getName() << ": [";

	bool first = true;
	for (const auto& value : accessor(data)) {
		if (!first)
			std::cout << ", ";
		std::cout << value;
		first = false;
	}

	std::cout << "]\n";
}

static void
printScalarVariant(const FieldDescriptor& field, const ScalarValueGetter& variant, const void* data)
{
	const auto visitor = [&](const auto& accessor) { printScalar(field, accessor, data); };
	std::visit(visitor, variant);
}

static void
printVectorVariant(const FieldDescriptor& field, const VectorValueGetter& variant, const void* data)
{
	const auto visitor = [&](const auto& accessor) { printVector(field, accessor, data); };
	std::visit(visitor, variant);
}

void TextOutputPlugin::processRecord(FlowRecordUniquePtr& flowRecord)
{
	std::ranges::for_each(m_fieldManager.getBiflowFields(), [&](const FieldDescriptor& fieldDescriptor) {
		if (!fieldDescriptor.isInRecord(*flowRecord.get())) {
			return;
		}

		const void* pluginExportData = flowRecord->getPluginContext(fieldDescriptor.getBitIndex());

		const auto& getter = fieldDescriptor.getValueGetter();
		std::visit(
			[&](const auto& variant) {
				using GetterT = std::decay_t<decltype(variant)>;
				if constexpr (std::is_same_v<GetterT, ScalarValueGetter>) {
					printScalarVariant(fieldDescriptor, variant, pluginExportData);
				} else if constexpr (std::is_same_v<GetterT, VectorValueGetter>) {
					printVectorVariant(fieldDescriptor, variant, pluginExportData);
				}
			},
			getter);
	});
}

} // namespace ipxp
