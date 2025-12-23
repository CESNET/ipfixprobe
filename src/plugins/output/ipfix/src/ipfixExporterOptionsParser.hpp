#pragma once

#include <chrono>
#include <cstdint>

#include <ipfixprobe/outputPlugin/outputOptionsParser.hpp>

namespace ipxp::output::ipfix {

struct IPFIXExporterOptionsParser : public OutputOptionsParser {
	constexpr static std::string_view LOCALHOST = "127.0.0.1";
	constexpr static uint16_t DEFAULT_PORT = 4739;
	constexpr static uint64_t DEFAULT_EXPORTER_ID = 0;
	constexpr static std::chrono::seconds DEFAULT_TEMPLATE_REFRESH_TIME = std::chrono::seconds(600);
	constexpr static uint16_t DEFAULT_MTU = 1500;

	IPFIXExporterOptionsParser(std::string_view params)
		: OutputOptionsParser("ipfix", "Output plugin for ipfix export")
	{
		register_option(
			"h",
			"host",
			"ADDR",
			"Remote collector address",
			[this](const char* arg) {
				connectionOptions.collector = arg;
				return true;
			},
			OptionFlags::RequiredArgument);
		register_option(
			"p",
			"port",
			"PORT",
			"Remote collector port",
			[this](const char* arg) {
				try {
					connectionOptions.collectorPort = std::strtoul(arg, nullptr, 10);
				} catch (...) {
					return false;
				}
				return true;
			},
			OptionFlags::RequiredArgument);
		register_option(
			"m",
			"mtu",
			"SIZE",
			"Maximum size of ipfix packet payload sent",
			[this](const char* arg) {
				try {
					connectionOptions.maximalTransmissionUnit = std::strtoul(arg, nullptr, 10);
				} catch (...) {
					return false;
				}
				return true;
			},
			OptionFlags::RequiredArgument);
		register_option(
			"u",
			"udp",
			"",
			"Use UDP protocol",
			[this](const char* arg) {
				(void) arg;
				connectionOptions.mode = Mode::UDP;
				return true;
			},
			OptionFlags::NoArgument);
		register_option(
			"n",
			"non-blocking-tcp",
			"",
			"Use non-blocking socket for TCP protocol",
			[this](const char* arg) {
				(void) arg;
				connectionOptions.mode = Mode::NON_BLOCKING_TCP;
				return true;
			},
			OptionFlags::NoArgument);
		register_option(
			"I",
			"id",
			"NUM",
			"Exporter identification",
			[this](const char* arg) {
				try {
					exporterOptions.observationDomainId = std::strtoul(arg, nullptr, 10);
				} catch (...) {
					return false;
				}
				return true;
			},
			OptionFlags::RequiredArgument);
		register_option(
			"d",
			"dir",
			"NUM",
			"Dir bit field value",
			[this](const char* arg) {
				try {
					exporterOptions.directionBitField = std::strtoul(arg, nullptr, 10);
				} catch (...) {
					return false;
				}
				return true;
			},
			OptionFlags::RequiredArgument);
		register_option(
			"t",
			"template",
			"NUM",
			"Template refresh rate (sec)",
			[this](const char* arg) {
				try {
					exporterOptions.templateRefreshTime
						= std::chrono::seconds(std::strtoul(arg, nullptr, 10));
				} catch (...) {
					return false;
				}
				return true;
			},
			OptionFlags::RequiredArgument);
		register_option(
			"v",
			"verbose",
			"",
			"Enable verbose mode",
			[this](const char* arg) {
				(void) arg;
				verbose = true;
				return true;
			},
			OptionFlags::NoArgument);
		register_option(
			"c",
			"lz4-compression",
			"",
			"Enable lz4 compression",
			[this](const char* arg) {
				(void) arg;
				lz4Options.emplace();
				return true;
			},
			OptionFlags::NoArgument);
		register_option(
			"s",
			"lz4-buffer-size",
			"",
			"Lz4 compression buffer size (default (minimum): mtu*3)",
			[this](const char* arg) {
				try {
					lz4Options.emplace(std::strtoul(arg, nullptr, 10));
				} catch (...) {
					return false;
				}
				return true;
			},
			OptionFlags::RequiredArgument);

		parse(params.data());
	}

	enum class Mode : uint8_t { UDP, NON_BLOCKING_TCP };

	struct LZ4Options {
		std::size_t bufferSize {0};
	};

	struct ConnectionOptions {
		std::string collector {std::string(LOCALHOST)};
		uint16_t collectorPort {DEFAULT_PORT};
		uint16_t maximalTransmissionUnit {DEFAULT_MTU};
		Mode mode = Mode::UDP;
	} connectionOptions;

	struct ExporterOptions {
		uint32_t observationDomainId {DEFAULT_EXPORTER_ID};
		uint32_t directionBitField {0};
		std::chrono::duration<uint32_t> templateRefreshTime {DEFAULT_TEMPLATE_REFRESH_TIME};
	} exporterOptions;

	std::optional<LZ4Options> lz4Options;
	bool verbose {false};
};

} // namespace ipxp::output::ipfix