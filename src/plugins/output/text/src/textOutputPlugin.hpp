#pragma once

#include "fieldDescriptor.hpp"
#include "outputPlugin.hpp"

namespace ipxp {

class TextOutputPlugin : public OutputPlugin {
public:
	TextOutputPlugin(const std::string& params, const FieldManager& manager, const std::vector<ProcessPluginEntry>& plugins)
		: OutputPlugin(manager, plugins)
	{
	}

	void processRecord(FlowRecordUniquePtr& flowRecord) override;
	
};

} // namespace ipxp
