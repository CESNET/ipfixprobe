#pragma once

#include "fieldManager.hpp"
#include "flowRecord.hpp"
#include "processPluginEntry.hpp"

namespace ipxp {

class OutputPlugin {
public:
	OutputPlugin(const FieldManager& fieldManager, const std::vector<ProcessPluginEntry>& plugins)
		: m_fieldManager(fieldManager)
		, m_plugins(plugins)
	{
	}

	virtual void processRecord(FlowRecordUniquePtr& flowRecord) = 0;

protected:
	const FieldManager& m_fieldManager;
	const std::vector<ProcessPluginEntry>& m_plugins;
	virtual ~OutputPlugin() = default;
};

} // namespace ipxp
