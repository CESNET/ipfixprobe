#include "dummyProcessPlugin.hpp"
#include "fieldManager.hpp"
#include "fieldSchema.hpp"
#include "flowRecord.hpp"
#include "flowRecordBuilder.hpp"
#include "outputField.hpp"
#include "processPlugin.hpp"
#include "textOutputPlugin.hpp"

int main()
{
	ipxp::FlowRecordBuilder builder;
	ipxp::FieldManager manager;
	ipxp::Packet packet;
	ipxp::PacketOfFlowData data;

	builder.addProcessPlugin("dummy", "params", manager);

	ipxp::FlowRecord flowRecord = builder.build();

	try {
		flowRecord.forEachPlugin(
			[&](ipxp::ProcessPlugin* plugin) { plugin->onFlowCreate(flowRecord, packet); });

		flowRecord.forEachPlugin(
			[&](ipxp::ProcessPlugin* plugin) { plugin->onFlowUpdate(flowRecord, packet, data); });
	} catch (std::exception& ex) {
		std::cout << ex.what() << "\n";
		return 1;
	}

	ipxp::TextOutputPlugin text;
	text.processRecord(flowRecord, manager);

	return 0;
}
