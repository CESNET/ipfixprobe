#include "flowRecordBuilder.hpp"
#include "processPluginBuilder.hpp"

namespace ipxp {

std::shared_ptr<FlowRecordBuilder> ProcessPlugins::rebuild()
{
	std::lock_guard<std::mutex> lock(m_mutex);

	std::vector<ProcessPluginEntry> enabledPlugins;
	// naplnit vector

	return std::make_shared<FlowRecordBuilder>(enabledPlugins);
}

} // namespace ipxp