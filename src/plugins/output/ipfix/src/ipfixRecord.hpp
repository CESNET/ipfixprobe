/**
 * @file ipfixRecord.hpp
 * @brief IPFIX record declaration.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * IPFIX record that represents a filled IPFIX template.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "ipfixBasicList.hpp"
#include "ipfixTemplate.hpp"
#include "protocolFieldMap.hpp"
#include "utils/byteUtils.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <boost/container/static_vector.hpp>
#include <flowRecord.hpp>

namespace ipxp::output::ipfix {

/**
 * @class IPFIXRecord
 * @brief Class representing an IPFIX record based on a given template and flow record.
 */
struct IPFIXRecord {
	/**
	 * @brief Constructs an IPFIXRecord with the specified protocol fields, flow record, and IPFIX
	 * template.
	 * @param protocolFields The protocol field map.
	 * @param flowRecord The flow record containing the data.
	 * @param ipfixTemplate The IPFIX template defining the structure of the record.
	 */
	IPFIXRecord(
		const ProtocolFieldMap& protocolFields,
		const FlowRecord& flowRecord,
		const IPFIXTemplate& ipfixTemplate) noexcept
		: protocolFields(protocolFields)
		, flowRecord(flowRecord)
		, ipfixTemplate(ipfixTemplate)
	{
	}

	const ProtocolFieldMap& protocolFields;
	const FlowRecord& flowRecord;
	const IPFIXTemplate& ipfixTemplate;
};

} // namespace ipxp::output::ipfix