#include "fieldSchema.hpp"
#include "icmp.hpp"

#include <functional>

#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>

namespace ipxp {

using AddHandler = std::function<void(const FieldHandler&, IcmpFields)>;

static void registerIcmpTypeField(FieldSchema& schema, AddHandler addHandler)
{
	const auto getterFunction = [](const void* context) {
		return reinterpret_cast<const IcmpPluginData*>(context)->type;
	};

	const FieldHandler icmpTypeHandler = schema.addScalarField("ICMP_TYPE", getterFunction);

	addHandler(icmpTypeHandler, IcmpFields::ICMP_TYPE);
}

static void registerIcmpCodeField(FieldSchema& schema, AddHandler addHandler)
{
	const auto getterFunction = [](const void* context) {
		return reinterpret_cast<const IcmpPluginData*>(context)->code;
	};

	const FieldHandler icmpCodeHandler = schema.addScalarField("ICMP_CODE", getterFunction);

	addHandler(icmpCodeHandler, IcmpFields::ICMP_CODE);
}

static void registerIcmpTypeCodeField(FieldSchema& schema, AddHandler addHandler)
{
	const auto getterFunction = [](const void* context) {
		const auto* icmpPluginData = reinterpret_cast<const IcmpPluginData*>(context);
		return static_cast<uint16_t>(icmpPluginData->type) << 8 | icmpPluginData->code;
	};

	const FieldHandler icmpTypeCodeHandler
		= schema.addScalarField("ICMP_TYPE_CODE", getterFunction);

	addHandler(icmpTypeCodeHandler, IcmpFields::ICMP_TYPE_CODE);
}

inline AddHandler createAddHandlerFunction(FieldHandlers<IcmpFields>& handlers)
{
	return [&handlers](const FieldHandler& handler, IcmpFields field) {
		handlers.insert(field, handler);
	};
}

void createFieldSchema(FieldManager& fieldManager, FieldHandlers<IcmpFields>& handlers)
{
	FieldSchema fieldSchema = fieldManager.createFieldSchema("icmp");

	const auto addHandlerFunction = createAddHandlerFunction(handlers);

	registerIcmpTypeField(fieldSchema, addHandlerFunction);
	registerIcmpCodeField(fieldSchema, addHandlerFunction);
	registerIcmpTypeCodeField(fieldSchema, addHandlerFunction);
}

IcmpPlugin::IcmpPlugin(const std::string& parameters, FieldManager& fieldManager)
{
	(void) parameters;

	createFieldSchema(fieldManager, m_fieldHandlers);
}

template<typename T>
static void parseTypeCode(const Packet& packet, IcmpPluginData& pluginData)
{
	const auto* icmpHeader = reinterpret_cast<const T*>(packet.payload);
	pluginData.type = icmpHeader->type;
	pluginData.code = icmpHeader->code;
}

void IcmpPlugin::parseIcmp(
	const FlowRecord& flowRecord,
	const Packet& packet,
	IcmpPluginData& pluginData)
{
	// if (packet.ipVersion == IPV4) {
	// 	parseTypeCode<icmphdr>(packet, pluginData);
	// } else {
	// 	parseTypeCode<icmp6_hdr>(packet, pluginData);
	// }

	m_fieldHandlers[IcmpFields::ICMP_TYPE].setAsAvailable(flowRecord);
	m_fieldHandlers[IcmpFields::ICMP_CODE].setAsAvailable(flowRecord);
	m_fieldHandlers[IcmpFields::ICMP_TYPE_CODE].setAsAvailable(flowRecord);
}

static bool isIcmpPacket(const Packet& packet) noexcept
{
	/*
	if (packet.l4Protocol != ICMP_V4 && packet.l4Protocol != ICMP_V6) {
		return false;
	}

	// TODO porovnat s velikosti cele ICMP header?
	constexpr std::size_t MIN_PAYLOAD_LENGTH = 16;
	if (packet.payload_len < MIN_PAYLOAD_LENGTH) {
		return false;
	}
	*/

	return true;
}

PluginInitResult IcmpPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	assert(pluginContext != nullptr && "Icmp: Plugin context must not be null");

	if (!isIcmpPacket(flowContext.packet)) {
		return {
			.constructionState = ConstructionState::NotConstructed,
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::NoAction,
		};
	}

	IcmpPluginData* pluginData
		= std::construct_at(reinterpret_cast<IcmpPluginData*>(pluginContext));

	parseIcmp(flowContext.flowRecord, flowContext.packet, *pluginData);

	return {
		.constructionState = ConstructionState::Constructed,
		.updateRequirement = UpdateRequirement::NoUpdateNeeded,
		.flowAction = FlowAction::NoAction,
	};
}

void IcmpPlugin::onDestroy(void* pluginContext)
{
	assert(pluginContext != nullptr && "Icmp: Plugin context must not be null");

	std::destroy_at(reinterpret_cast<IcmpPluginData*>(pluginContext));
}

PluginDataMemoryLayout IcmpPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(IcmpPluginData),
		.alignment = alignof(IcmpPluginData),
	};
}

} // namespace ipxp
