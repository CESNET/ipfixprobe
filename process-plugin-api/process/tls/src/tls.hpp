/**
 * @file
 * @brief Plugin for enriching flows for tls data.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Karel Hynek <Karel.Hynek@cesnet.cz>
 * @author Andrej Lukacovic lukacan1@fit.cvut.cz
 * @author Jonas Mücke <jonas.muecke@tu-dresden.de>
 * @author Pavel Siska <siska@cesnet.cz>
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <string>
#include <span>

#include <processPlugin.hpp>
#include <fieldManager.hpp>
#include <tlsParser/tlsParser.hpp>

#include "tlsExport.hpp"
#include "tlsFields.hpp"

namespace ipxp {

/**
 * \brief Flow cache plugin for parsing TLs packets.
 */
class TLSPlugin : public ProcessPlugin {
public:
	TLSPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet) override;

	void onFlowExport(FlowRecord& flowRecord) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~TLSPlugin() override = default;

	TLSPlugin(const TLSPlugin& other) = default;
	TLSPlugin(TLSPlugin&& other) = delete;

private:
	constexpr bool parseTLS(
	std::span<const std::byte> payload, const uint8_t l4Protocol) noexcept;
	void saveJA3(const TLSParser& parser) noexcept;
	void saveJA4(const TLSParser& parser, const uint8_t l4Protocol) noexcept;
	bool parseClientHelloExtensions(TLSParser& parser) noexcept;
	bool parseServerHelloExtensions(TLSParser& parser) noexcept;

	FieldHandlers<TLSFields> m_fieldHandlers;
	TLSExport m_exportData;

	std::optional<TLSParser::EllipticCurvePointFormats> m_pointFormats;
	std::optional<TLSParser::ALPNs> m_alpns;
	std::optional<TLSParser::SupportedVersions> m_supportedVersions;
	std::optional<TLSParser::SupportedGroups> m_supportedGroups;
	std::optional<TLSParser::SignatureAlgorithms> m_signatureAlgorithms;
	std::optional<TLSParser::ServerNames> m_serverNames;
	bool m_clientHelloParsed{false};
	bool m_serverHelloParsed{false};



};

} // namespace ipxp
