//
// Created by ivrana on 8/10/21.
//

#ifndef IPFIXPROBE_FLEXPROBE_TCP_TRACKING_H
#define IPFIXPROBE_FLEXPROBE_TCP_TRACKING_H

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/ipfix-elements.hpp>

namespace ipxp {

enum class TrackerState {
    BEHIND,
    INLINE,
    AHEAD
};

enum class FlowState {
    OK,
    PACKET_LOSS
};

enum class TcpResult {
    OK,
    INCOMPLETE
};

struct TcpTrackingData : public RecordExt {
    static int REGISTERED_ID;

    TrackerState tracker_state[2];
    TcpResult result;
    std::uint32_t expected_seq[2];

    TcpTrackingData()
        : RecordExt(REGISTERED_ID),
          tracker_state{TrackerState::INLINE, TrackerState::INLINE},
          result(TcpResult::OK),
          expected_seq{0, 0}
    {}

    virtual int fill_ipfix(uint8_t *buffer, int size)
    {
        *buffer = std::underlying_type<TcpResult>::type(result);
        return sizeof(std::uint8_t);
    }

    const char **get_ipfix_tmplt() const
    {
       static const char *ipfix_template[] = {
             IPFIX_FLEXPROBE_TCP_TEMPLATE(IPFIX_FIELD_NAMES)
             nullptr
       };
       return ipfix_template;
    }
};

class FlexprobeTcpTracking : public ProcessPlugin
{
private:
    FlowState check_(TcpTrackingData& td, std::uint32_t tcp_seq, unsigned direction);

    std::uint32_t advance_expected_seq_(std::uint32_t current_seq, std::uint16_t payload_len, bool syn, bool fin);
public:
    FlexprobeTcpTracking() = default;

    void init(const char *params) {} // TODO
    void close() {} // TODO
    RecordExt *get_ext() const { return new TcpTrackingData(); }
    OptionsParser *get_parser() const { return new OptionsParser("flexprobe-tcp", "Parse flexprobe data"); }
    std::string get_name() const { return "flexprobe-tcp"; }
    FlexprobeTcpTracking *copy() override
    {
        return new FlexprobeTcpTracking(*this);
    }

    int post_create(Flow &rec, const Packet &pkt) override;

    int post_update(Flow &rec, const Packet &pkt) override;
};

}
#endif //IPFIXPROBE_FLEXPROBE_TCP_TRACKING_H
