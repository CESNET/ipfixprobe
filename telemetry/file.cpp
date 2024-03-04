/**
 * @file
 * @author Lukas Hutak <lukas.hutak@hotmail.com>
 * @brief Telemetry file
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "file.hpp"

namespace ipxp::Telemetry {

File::File(const std::shared_ptr<Node>& parent, std::string_view name, FileOps ops)
    : Node(parent, name)
    , m_ops(std::move(ops))
{
    /*
     * Note: The file cannot NOT be added to the parent as an entry here, since
     * this object hasn't been fully initialized yet and shared_from_this()
     * doesn't work in constructors.
     */
}

bool File::hasRead()
{
    std::lock_guard lock(getMutex());
    return bool {m_ops.read};
}

bool File::hasClear()
{
    std::lock_guard lock(getMutex());
    return bool {m_ops.clear};
}

Content File::read()
{
    std::lock_guard lock(getMutex());

    if (!m_ops.read) {
        std::string err = "File::read('" + getFullPath() + "') operation not supported";
        throw NodeException(err);
    }

    return m_ops.read();
}

void File::clear()
{
    std::lock_guard lock(getMutex());

    if (!m_ops.clear) {
        std::string err = "File::clear('" + getFullPath() + "') operation not supported";
        throw NodeException(err);
    }

    m_ops.clear();
}

void File::disable()
{
    std::lock_guard lock(getMutex());
    m_ops = {};
}

} // namespace ipxp::Telemetry
