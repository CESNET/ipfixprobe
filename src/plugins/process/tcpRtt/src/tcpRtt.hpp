/**
 * @file
 * @brief Plugin for accounting round trip time of tcp handshakes.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <limits>
#include <memory>
#include <sstream>

#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-basiclist.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/processPlugin.hpp>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

namespace ipxp {

#define TCPRTT_UNIREC_TEMPLATE "TCPRTT_TIME"
UR_FIELDS(uint64 TCPRTT_TIME)

/**
 * @brief Convert timeval struct to count of milliseconds since epoch
 * @param timeval Timeval to convert
 * @return Count of milliseconds since epoch
 */
constexpr static inline uint64_t timeval_to_msec(timeval timeval) noexcept
{
	constexpr size_t MSEC_IN_SEC = 1'000;
	constexpr size_t USEC_IN_MSEC = 1'000;
	return timeval.tv_sec * MSEC_IN_SEC + timeval.tv_usec / USEC_IN_MSEC;
}

/**
 * \brief Flow record extension header for storing observed handshake timestamps.
 */
struct RecordExtTCPRTT : public RecordExt {
private:
	constexpr static timeval NO_TIMESTAMP = timeval {std::numeric_limits<time_t>::min(), 0};

	constexpr inline static bool has_no_value(timeval timeval) noexcept
	{
		return timeval.tv_sec == NO_TIMESTAMP.tv_sec && timeval.tv_usec == NO_TIMESTAMP.tv_usec;
	}

public:
	timeval tcp_syn_timestamp {NO_TIMESTAMP}; ///< Timestamp of last observed TCP SYN packet
	timeval tcp_synack_timestamp {NO_TIMESTAMP}; ///< Timestamp of last observed TCP SYNACK packet

	RecordExtTCPRTT(int pluginID)
		: RecordExt(pluginID)
	{
	}

#ifdef WITH_NEMEA
	virtual void fill_unirec(ur_template_t* tmplt, void* record)
	{
		if (has_no_value(tcp_syn_timestamp) || has_no_value(tcp_synack_timestamp)) {
			ur_set(tmplt, record, F_TCPRTT_TIME, std::numeric_limits<uint64_t>::max());
			return;
		}

		const ur_time_t round_trip_time = ur_timediff(
			ur_time_from_sec_usec(tcp_synack_timestamp.tv_sec, tcp_synack_timestamp.tv_usec),
			ur_time_from_sec_usec(tcp_syn_timestamp.tv_sec, tcp_syn_timestamp.tv_usec));
		ur_set(tmplt, record, F_TCPRTT_TIME, round_trip_time);
	}

	const char* get_unirec_tmplt() const { return TCPRTT_UNIREC_TEMPLATE; }

#endif // ifdef WITH_NEMEA

	int fill_ipfix(uint8_t* buffer, int size) override
	{
		if (size < static_cast<ssize_t>(sizeof(uint64_t))) {
			return -1;
		}

		if (has_no_value(tcp_syn_timestamp) || has_no_value(tcp_synack_timestamp)) {
			*reinterpret_cast<uint64_t*>(buffer) = std::numeric_limits<uint64_t>::max();
			return static_cast<int>(sizeof(uint64_t));
		}

		const uint64_t round_trip_time
			= timeval_to_msec(tcp_synack_timestamp) - timeval_to_msec(tcp_syn_timestamp);
		*reinterpret_cast<uint64_t*>(buffer) = round_trip_time;
		return static_cast<int>(sizeof(round_trip_time));
	}

	const char** get_ipfix_tmplt() const
	{
		static const char* ipfix_template[] = {IPFIX_TLS_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};

		return ipfix_template;
	}

	std::string get_text() const override
	{
		std::ostringstream out;

		if (has_no_value(tcp_syn_timestamp) || has_no_value(tcp_synack_timestamp)) {
			out << "tcprtt = UNKNOWN";
		} else {
			out << "tcprtt = "
				<< timeval_to_msec(tcp_synack_timestamp) - timeval_to_msec(tcp_syn_timestamp);
		}

		return out.str();
	}
};

class TCPRTTPlugin : public ProcessPlugin {
public:
	TCPRTTPlugin(const std::string& params, int pluginID);

	TCPRTTPlugin(const TCPRTTPlugin&) noexcept;

	~TCPRTTPlugin() override = default;

	void init(const char* params) override;

	OptionsParser* get_parser() const override;

	std::string get_name() const override;

	RecordExtTCPRTT* get_ext() const override;

	ProcessPlugin* copy();

	int post_create(Flow& rec, const Packet& pkt) override;

	int pre_update(Flow& rec, Packet& pkt) override;

private:
	void update_tcp_rtt_record(Flow& rec, const Packet& pkt) noexcept;

	std::unique_ptr<RecordExtTCPRTT> m_prealloced_extension {get_ext()};
};

} // namespace ipxp
