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
	FlowRecordBuilder builder;
	FieldManager manager;
	Packet packet;

	builder.addProcessPlugin("dummy", "params", manager);

	FlowRecord flowRecord = builder.build();

	try {
		flowRecord.forEachPlugin(
			[&](ProcessPlugin* plugin) { plugin->onFlowCreate(flowRecord, packet); });

		flowRecord.forEachPlugin(
			[&](ProcessPlugin* plugin) { plugin->onFlowUpdate(flowRecord, packet); });
	} catch (std::exception& ex) {
		std::cout << ex.what() << "\n";
		return 1;
	}

	TextOutputPlugin text;
	text.processRecord(flowRecord, manager);

	return 0;
}
