#pragma once

#include "ipfixRecord.hpp"

namespace ipxp::output::ipfix {

class IPFIXRecordWriter {
public:
	/**
	 * @brief Writes the IPFIX record to the given byte writer.
	 * @param outputWriter The byte writer to write the record to.
	 */
	static bool writeRecordTo(const IPFIXRecord& record, utils::ByteWriter& outputWriter) noexcept;
};

} // namespace ipxp::output::ipfix