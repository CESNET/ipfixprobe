#pragma once

#include "connection/connectionFactory.hpp"
#include "ipfixExporterElementsParser.hpp"
#include "ipfixTemplate.hpp"
#include "ipfixTemplateBuilder.hpp"
#include "protocolFieldMap.hpp"

#include <vector>

namespace ipxp::output::ipfix {

class IPFIXTemplateManager {
public:
	explicit IPFIXTemplateManager(
		const IPFIXExporterElementsParser& elementsParser,
		const ProtocolFieldMap& protocolFields,
		ConnectionFactory::Mode connectionMode,
		std::chrono::duration<uint32_t> templateRefreshTime)
		: m_connectionMode(connectionMode)
	{
		createTemplates(elementsParser, protocolFields);
	}

	auto& getTemplate(this auto&& self, const std::size_t templateIndex) noexcept
	{
		return self.m_templates[templateIndex];
	}

	static std::size_t calculateTemplateIndex(
		const FlowRecord& flowRecord,
		const ProtocolFieldMap& protocolFields) noexcept;

	bool templateNeedsRefresh(const std::size_t templateIndex) const noexcept
	{
		if (m_connectionMode == ConnectionFactory::Mode::UDP
			&& std::chrono::steady_clock::now() - m_templates[templateIndex].lastSendTime
				>= m_templateRefreshTime) {
			return true;
		}

		if ((m_connectionMode == ConnectionFactory::Mode::NON_BLOCKING_TCP
			 || m_connectionMode == ConnectionFactory::Mode::BLOCKING_TCP)
			&& m_templates[templateIndex].lastSendTime
				== std::chrono::steady_clock::time_point {}) {
			return true;
		}

		return false;
	}

	void onTemplateSent(const std::size_t templateIndex) noexcept
	{
		m_templates[templateIndex].lastSendTime = std::chrono::steady_clock::now();
	}

private:
	void createTemplates(
		const IPFIXExporterElementsParser& elementsParser,
		const ProtocolFieldMap& protocolFields);

	std::vector<IPFIXTemplate> m_templates;
	ConnectionFactory::Mode m_connectionMode;
	std::chrono::duration<uint32_t> m_templateRefreshTime;
};

} // namespace ipxp::output::ipfix