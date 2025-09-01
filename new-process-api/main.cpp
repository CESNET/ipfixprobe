#include "fieldManager.hpp"
#include "flowKey.hpp"
#include "flowRecordBuilder.hpp"
#include "icmp.hpp"
#include "processPluginBuilder.hpp"
#include "textOutputPlugin.hpp"

#include <iostream>

using namespace ipxp;

int main()
{
	FieldManager fieldManager;
	ProcessPlugins processPlugins(fieldManager);

	processPlugins.addProcessPlugin("TestDummy", "Params");

	processPlugins.disableProcessPlugin("TestDummy");
	processPlugins.enableProcessPlugin("TestDummy");

	const FlowKeyLayout VlanFlowKeyLayout{20, 4};
	FlowRecordBuilder builder(processPlugins.getEntries(), VlanFlowKeyLayout);

	builder.printLayoutInfo();

	auto flowRecord = builder.build();

	/**
	processPlugins.forEachPlugin(
		flowRecord.get(),
		[&](FlowRecord* flowRecord, ProcessPlugin* plugin, void* pluginContext) {
			plugin->onInit(*flowRecord, pluginContext, Packet(), PacketFeatures());
		});
	*/

	TextOutputPlugin textOutputPlugin(fieldManager, processPlugins.getEntries());
	textOutputPlugin.processRecord(flowRecord);

	return 0;
}
