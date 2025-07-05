#pragma once

#include "flowRecordCtt.hpp"
#include "cttController.hpp"

#include <vector>
#include <memory>

namespace ipxp {

class CttRemoveQueue
{
public:

    CttRemoveQueue() noexcept;

    void set_buffer(FlowRecordCtt* buffer, size_t size) noexcept;

    void set_ctt_controller(CttController* ctt_controller) noexcept;

    FlowRecordCtt** find(size_t hash) noexcept;
    
    FlowRecordCtt** find_by_flowhash(size_t hash) noexcept;

    FlowRecordCtt* add(FlowRecordCtt* flow);

    size_t size() const noexcept;

    struct RequestCounts {
        size_t sent_requests{0};
        size_t lost_requests{0};
    };

    RequestCounts resend_lost_requests(const timeval now) noexcept;

private:

    void shrink() noexcept;

    FlowRecordCtt* m_flows;
    size_t m_flows_capacity;
    std::unique_ptr<FlowRecordCtt*[]> m_flow_table;
    size_t m_last_index;
    size_t m_export_index{0};
    CttController* m_ctt_controller;
};



} // namespace ipxp