#include "cttRemoveQueue.hpp"
#include "../../cache/src/fragmentationCache/timevalUtils.hpp"

#include <algorithm>

namespace ipxp
{

CttRemoveQueue::CttRemoveQueue() noexcept
    : m_last_index(0)
{
}

void CttRemoveQueue::set_buffer(FlowRecordCtt* buffer, size_t size) noexcept
{
    m_flows = buffer;
    m_flows_capacity = size;
    m_flow_table = std::make_unique<FlowRecordCtt*[]>(size);
    std::for_each(m_flow_table.get(), m_flow_table.get() + size, [index = 0, this](FlowRecordCtt*& flow) mutable {
        flow = &m_flows[index++];
    });
}

void CttRemoveQueue::set_ctt_controller(CttController* ctt_controller) noexcept
{
    m_ctt_controller = ctt_controller;
}

FlowRecordCtt** CttRemoveQueue::find(size_t hash) noexcept
{
    for (size_t index = 0; index < m_last_index; index++) {
        if (!m_flow_table[index]->is_empty() && m_flow_table[index]->belongs(hash)) {
            return &m_flow_table[index];                
        } 
    }
    return nullptr;
}

FlowRecordCtt** CttRemoveQueue::find_by_flowhash(size_t hash) noexcept
{
    for (size_t index = 0; index < m_last_index; index++) {
        if (!m_flow_table[index]->is_empty() && m_flow_table[index]->m_flow.flow_hash_ctt == hash) {
            return &m_flow_table[index];                
        } 
    }
    return nullptr;
}

FlowRecordCtt* CttRemoveQueue::add(FlowRecordCtt* flow)
{
    if (m_last_index == m_flows_capacity) {
        throw std::runtime_error("CttRemoveQueue is full");
    }

    for (size_t index = 0; index < m_last_index; index++) {
        if (m_flow_table[index]->is_empty()) {
            std::swap(m_flow_table[index], flow);
            shrink();
            return flow;
        }
    }
    std::swap(m_flow_table[m_last_index], flow);
    m_last_index++;
    shrink();
    return flow;
}

void CttRemoveQueue::shrink() noexcept
{
    for (; m_last_index > 0 && m_flow_table[m_last_index - 1]->is_empty(); m_last_index--);
}

size_t CttRemoveQueue::size() const noexcept
{
    return m_last_index;
}

CttRemoveQueue::RequestCounts CttRemoveQueue::resend_lost_requests(const timeval now) noexcept
{
    constexpr size_t BLOCK_SIZE = 16;
    size_t sent_requests = 0;
    size_t lost_requests = 0;

    for (size_t index = m_export_index; index < m_export_index + BLOCK_SIZE && index < m_last_index; index++) {
        if (m_flow_table[index]->is_empty() || !m_flow_table[index]->is_in_ctt()) {
            continue;
        }

        if (!m_flow_table[index]->is_waiting_ctt_response() || now > *m_flow_table[index]->last_request_time + CTT_REQUEST_TIMEOUT) {
            if (m_flow_table[index]->is_waiting_ctt_response()) {
                lost_requests++;
            }
            sent_requests++;
            m_ctt_controller->export_record(m_flow_table[index]->m_flow.flow_hash_ctt);
            m_flow_table[index]->last_request_time = now;
        } 
    } 
    m_export_index = m_export_index + BLOCK_SIZE;
    m_export_index = m_export_index > m_last_index ? 0 : m_export_index;
    return {sent_requests, lost_requests};
}

}