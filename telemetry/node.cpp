/**
 * @file
 * @author Lukas Hutak <lukas.hutak@hotmail.com>
 * @brief Telemetry node
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <algorithm>
#include <cctype>

#include "node.hpp"

namespace ipxp::Telemetry {

Node::Node(std::shared_ptr<Node> parent, std::string_view name)
    : m_name(name)
    , m_parent(std::move(parent))
{
    if (m_parent == nullptr) {
        throwNodeException("parent cannot be nullptr");
    }

    checkName(m_name);
}

static bool isValidCharacter(char character)
{
    if (std::isalnum(character) != 0) {
        return true;
    }

    if (character == '-' || character == '_') {
        return true;
    }

    return false;
}

std::string Node::getFullPath()
{
    std::string result;

    if (!m_parent) {
        return m_name.empty() ? "/" : getName();
    }

    result = m_parent->getFullPath();
    if (result.back() != '/') {
        result += '/';
    }

    return result + getName();
}

void Node::checkName(std::string_view name)
{
    if (name.empty()) {
        throwNodeException("empty name is not allowed");
    }

    const auto* const pos = std::find_if_not(name.begin(), name.end(), isValidCharacter);
    if (pos != name.end()) {
        std::string err = "prohibited character '" + std::to_string(*pos) + "'";
        throwNodeException(err);
    }
}

void Node::throwNodeException(std::string_view err)
{
    const std::string msg = "Node('" + getFullPath() + "') has failed: ";
    throw NodeException(msg + std::string(err));
}

} // namespace ipxp::Telemetry
