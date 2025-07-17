/**
 * @file
 * @brief Plugin for parsing basicplus traffic.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <sstream>
#include <string>

//#include <ipfixprobe/byte-utils.hpp>
//#include <ipfixprobe/flowifc.hpp>
//#include <ipfixprobe/ipfix-elements.hpp>
//#include <ipfixprobe/packet.hpp>
//#include <ipfixprobe/processPlugin.hpp>

#include <processPlugin.hpp>
#include <fieldManager.hpp>

#include "basicPlusExport.hpp"
#include "basicPlusFields.hpp"

namespace ipxp {

/**
 * \brief Basic flow cache plugin.
 */
class BasicPlusPlugin 
	: private FieldHandlers<BasicPlusFields>
	, public ProcessPlugin {
public:
	BasicPlusPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet, const PacketOfFlowData& data) override;

	void onFlowExport() override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~BasicPlusPlugin() override = default;

	BasicPlusPlugin(const BasicPlusPlugin& other) = default;
	BasicPlusPlugin(BasicPlusPlugin&& other) = delete;

private:
	BasicPlusExport m_exportData;
};

} // namespace ipxp
