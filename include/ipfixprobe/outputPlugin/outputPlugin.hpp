#pragma once

#include "../api.hpp"
#include "fieldManager.hpp"
#include "flowRecord.hpp"
#include "processPluginEntry.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// #include "../pluginFactory/pluginFactory.hpp"

namespace ipxp {

using namespace process;

class IPXP_API OutputPlugin {
public:
	OutputPlugin(const FieldManager& fieldManager, const std::vector<ProcessPluginEntry>& plugins)
		: m_fieldManager(fieldManager)
		, m_plugins(plugins)
	{
	}

	virtual void processRecord(FlowRecordUniquePtr& flowRecord) = 0;

	std::size_t getDroppedCount() const noexcept { return m_dropped; }

	virtual ~OutputPlugin() = default;

	constexpr static std::size_t DEFAULT_EXPORTER_ID = 1;

protected:
	const FieldManager& m_fieldManager;
	const std::vector<ProcessPluginEntry>& m_plugins;
	std::size_t m_dropped = 0;
	std::size_t m_seen = 0;
};

template<typename Base, typename... Args>
class IPXP_API PluginFactory;

/**
 * @brief Type alias for the OutputPlugin factory.
 *
 * Provides a factory for creating OutputPlugin instances using a string-based constructor.
 */
using OutputPluginFactory = PluginFactory<
	OutputPlugin,
	const std::string&,
	const FieldManager&,
	const std::vector<ProcessPluginEntry>&>;

} // namespace ipxp
