#pragma once

#include "fieldHandler.hpp"
#include "fieldManager.hpp"
#include "fieldSchema.hpp"
#include "processPlugin.hpp"
#include "flowRecord.hpp"

enum Direction : std::size_t { Forward = 0, Reverse = 1 };

template<typename T>
struct DirectionalField {
	T values[2];

	T& operator[](Direction d) { return values[static_cast<std::size_t>(d)]; }
	const T& operator[](Direction d) const { return values[static_cast<std::size_t>(d)]; }
};

/*
struct DummyExport {
	uint8_t ipTtl;
	uint8_t ipTtlRev;
	uint8_t ipFlag;
	uint8_t ipFlagRev;
	uint16_t tcpWindow = 100;
	uint16_t tcpWindowRev;
	uint64_t tcpOption;
	uint64_t tcpOptionRev;
	uint32_t tcpMss;
	uint32_t tcpMssRev;
	uint16_t tcpSynSize;
	std::vector<uint64_t> packets;
	std::vector<uint64_t> packetsRev;
};
*/

struct DummyExport {
	DirectionalField<uint8_t> ipTtl;
	DirectionalField<uint8_t> ipFlag;
	DirectionalField<uint16_t> tcpWindow;
	DirectionalField<uint64_t> tcpOption;
	DirectionalField<uint32_t> tcpMss;
	uint16_t tcpSynSize;
	DirectionalField<std::vector<uint64_t>> packets;
};

enum class DummyFields : std::size_t {
	IP_TTL = 0,
	IP_TTL_REV,
	IP_FLG,
	IP_FLG_REV,
	TCP_WIN,
	TCP_WIN_REV,
	TCP_OPT,
	TCP_OPT_REV,
	TCP_MSS,
	TCP_MSS_REV,
	TCP_SYN_SIZE,
	PACKETS,
	PACKETS_REV,
	FIELDS_SIZE,
};

static FieldSchema createDummySchema()
{
	FieldSchema schema("basicplus");

	schema.addScalarField<uint8_t>(
		"IP_TTL",
		FieldDirection::Forward,
		offsetof(DummyExport, ipTtl.values[Direction::Forward]));
	schema.addScalarField<uint8_t>(
		"IP_TTL_REV",
		FieldDirection::Reverse,
		offsetof(DummyExport, ipTtl.values[Direction::Reverse]));
	schema.addScalarField<uint8_t>(
		"IP_FLG",
		FieldDirection::Forward,
		offsetof(DummyExport, ipFlag.values[Direction::Forward]));
	schema.addScalarField<uint8_t>(
		"IP_FLG_REV",
		FieldDirection::Reverse,
		offsetof(DummyExport, ipFlag.values[Direction::Reverse]));
	schema.addScalarField<uint16_t>(
		"TCP_WIN",
		FieldDirection::Forward,
		offsetof(DummyExport, tcpWindow.values[Direction::Forward]));
	schema.addScalarField<uint16_t>(
		"TCP_WIN_REV",
		FieldDirection::Reverse,
		offsetof(DummyExport, tcpWindow.values[Direction::Reverse]));
	schema.addScalarField<uint64_t>(
		"TCP_OPT",
		FieldDirection::Forward,
		offsetof(DummyExport, tcpOption.values[Direction::Forward]));
	schema.addScalarField<uint64_t>(
		"TCP_OPT_REV",
		FieldDirection::Reverse,
		offsetof(DummyExport, tcpOption.values[Direction::Reverse]));
	schema.addScalarField<uint32_t>(
		"TCP_MSS",
		FieldDirection::Forward,
		offsetof(DummyExport, tcpMss.values[Direction::Forward]));
	schema.addScalarField<uint32_t>(
		"TCP_MSS_REV",
		FieldDirection::Reverse,
		offsetof(DummyExport, tcpMss.values[Direction::Reverse]));
	schema.addScalarField<uint16_t>(
		"TCP_SYN_SIZE",
		FieldDirection::DirectionalIndifferent,
		offsetof(DummyExport, tcpSynSize));

	schema.addVectorField<uint64_t>(
		"PACKETS",
		FieldDirection::Forward,
		[](const void* thisPtr) -> std::span<const uint64_t> {
			return reinterpret_cast<const DummyExport*>(thisPtr)
				->packets.values[Direction::Forward];
		});

	schema.addVectorField<uint64_t>(
		"PACKETS_REV",
		FieldDirection::Forward,
		[](const void* thisPtr) -> std::span<const uint64_t> {
			return reinterpret_cast<const DummyExport*>(thisPtr)
				->packets.values[Direction::Reverse];
		});

	schema.addBiflowPair("IP_TTL", "IP_TTL_REV");
	schema.addBiflowPair("IP_FLG", "IP_FLG_REV");
	schema.addBiflowPair("TCP_WIN", "TCP_WIN_REV");
	schema.addBiflowPair("TCP_OPT", "TCP_OPT_REV");
	schema.addBiflowPair("TCP_MSS", "TCP_MSS_REV");
	schema.addBiflowPair("PACKETS", "PACKETS_REV");

	return schema;
}

class DummyPlugin
	: private FieldHandlers<DummyFields>
	, public ProcessPlugin {
public:
	DummyPlugin(const std::string& params, FieldManager& manager)
	{
		const FieldSchema schema = createDummySchema();
		const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

		(void) params;

		m_fieldHandlers[DummyFields::TCP_WIN] = schemaHandler.getFieldHandler("TCP_WIN");
		m_fieldHandlers[DummyFields::TCP_OPT] = schemaHandler.getFieldHandler("TCP_OPT");
		m_fieldHandlers[DummyFields::TCP_OPT_REV] = schemaHandler.getFieldHandler("TCP_OPT_REV");
		m_fieldHandlers[DummyFields::PACKETS] = schemaHandler.getFieldHandler("PACKETS");
		m_fieldHandlers[DummyFields::PACKETS_REV] = schemaHandler.getFieldHandler("PACKETS_REV");
		// je potreba inicializovat vsechny fieldy
	}

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override
	{
		(void) packet;

		m_exportData.tcpOption[Direction::Forward] = 156;
		m_exportData.tcpOption[Direction::Reverse] = 1689;

		// kdyz field dostane hodnotu, je potreba ho oznacit jako dostupny

		m_fieldHandlers[DummyFields::TCP_OPT].setAsAvailable(flowRecord);
		m_fieldHandlers[DummyFields::TCP_OPT_REV].setAsAvailable(flowRecord);

		return FlowAction::RequestNoData;
	}

	FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet) override
	{
		(void) flowRecord;
		(void) packet;

		m_exportData.packets[Direction::Forward] = {1, 2, 3, 4, 5, 6};
		m_fieldHandlers[DummyFields::PACKETS].setAsAvailable(flowRecord);

		return FlowAction::RequestNoData;
	}

	void onFlowExport() override {}

	const void* getExportData() const noexcept override { return &m_exportData; }

	ProcessPlugin* clone(std::byte* constructAtAddress) const override
	{
		return std::construct_at(reinterpret_cast<DummyPlugin*>(constructAtAddress), *this);
	}

	std::string getName() const override { return "DummyPlugin"; }

	~DummyPlugin() override {}

	DummyPlugin(const DummyPlugin& other) = default;
	DummyPlugin(DummyPlugin&& other) = delete;

private:
	DummyExport m_exportData;
};
