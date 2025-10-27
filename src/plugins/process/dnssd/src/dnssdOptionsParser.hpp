/**
 * @file dnssdOptionsParser.hpp
 * @brief Declaration of DNSSDOptionsParser for DNS-SD plugin options.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <optional>
#include <string>
#include <variant>

#include <ipfixprobe/options.hpp>

namespace ipxp::process::dnssd {

class DNSSDOptionsParser : public OptionsParser {
public:
	class ProcessAllTxtRecords {};
	using TxtProcessingMode = std::optional<std::variant<ProcessAllTxtRecords, std::string>>;
	TxtProcessingMode mode {std::nullopt};

	DNSSDOptionsParser()
		: OptionsParser("dnssd", "Processing plugin for parsing DNS service discovery packets")
	{
		register_option(
			"t",
			"txt",
			"FILE",
			"Activates processing of all txt records. Allow to specify whitelist txt records file "
			"(file line format: service.domain,txt_key1,txt_key2,...)",
			[this](const char* value) {
				if (value != nullptr) {
					mode = std::string(value);
				} else {
					mode = ProcessAllTxtRecords {};
				}
				return true;
			},
			OptionFlags::OptionalArgument);
	}
};

} // namespace ipxp