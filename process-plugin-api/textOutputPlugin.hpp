#pragma once

#include "outputField.hpp"
#include "outputPlugin.hpp"

template<typename T>
static void
printScalar(const OutputField& field, const ScalarAccessor<T>& accessor, const void* data)
{
	std::cout << "[" << field.getGroup() << "] " << field.getName() << ": " << accessor(data)
			  << "\n";
}

template<typename T>
static void
printVector(const OutputField& field, const VectorAccessor<T>& accessor, const void* data)
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
printScalarVariant(const OutputField& field, const ScalarValueGetter& variant, const void* data)
{
	const auto visitor = [&](const auto& accessor) { printScalar(field, accessor, data); };
	std::visit(visitor, variant);
}

static void
printVectorVariant(const OutputField& field, const VectorValueGetter& variant, const void* data)
{
	const auto visitor = [&](const auto& accessor) { printVector(field, accessor, data); };
	std::visit(visitor, variant);
}

class TextOutputPlugin : public OutputPlugin {
public:
	void processRecord(FlowRecord& flowRecord, FieldManager& manager) override
	{
		auto outputFields = manager.getFields();

		auto fn = [&](ProcessPlugin* processPlugin) {
			const void* pluginExportData = processPlugin->getExportData();

			for (const auto& outputField : outputFields) {
				if (!outputField.isInRecord(flowRecord)) {
					continue;
				}

				const auto& getter = outputField.getValueGetter();

				std::visit(
					[&](const auto& variant) {
						using GetterT = std::decay_t<decltype(variant)>;
						if constexpr (std::is_same_v<GetterT, ScalarValueGetter>) {
							printScalarVariant(outputField, variant, pluginExportData);
						} else if constexpr (std::is_same_v<GetterT, VectorValueGetter>) {
							printVectorVariant(outputField, variant, pluginExportData);
						}
					},
					getter);
			}
		};

		flowRecord.forEachPlugin(fn);
	}
};
