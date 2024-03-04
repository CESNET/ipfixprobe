/**
 * @file
 * @author Lukas Hutak <lukas.hutak@hotmail.com>
 * @brief Telemetry file
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <functional>

#include "content.hpp"
#include "node.hpp"

namespace ipxp::Telemetry {

class Directory;

/**
 * @brief File I/O operations.
 *
 * Asynchronously called function implemented by a file. All functions are optional.
 */
struct FileOps {
    std::function<Content()> read = nullptr;
    std::function<void()> clear = nullptr;
};

/**
 * @brief File entry.
 *
 * The class allows an asynchronous visitor to obtain telemetry information or interact
 * with the application component in some other way. The class provides a number of optional
 * I/O operations (callbacks) that can be implemented and the visitor can use.
 *
 * @warning
 *   If an object is referenced within I/O operations (callbacks), it must be released or
 *   otherwise destroyed after this file instance. There is a risk that, in the case of
 *   an asynchronous request, the object may be accessed during its destruction. If the
 *   correct order of release/destruction cannot be guaranteed, the disable() function can
 *   be used to block I/O operations (callbacks) from being called.
 */
class File : public Node {
public:
    ~File() override = default;

    // Object cannot be copied or moved as it would break references from directories.
    File(const File& other) = delete;
    File& operator=(const File& other) = delete;
    File(File&& other) = delete;
    File& operator=(File&& other) = delete;

    /** Test whether the file supports read operation. */
    bool hasRead();
    /** Test whether the file supports clear operation. */
    bool hasClear();

    /**
     * @brief Execute read operation.
     * @return Formatted content.
     * @throw NodeException if the operation is not supported.
     */
    Content read();
    /**
     * @brief Execute clear operation.
     * @throw NodeException if the operation is not supported.
     */
    void clear();

    /**
     * @brief Disable all I/O operations (callbacks).
     *
     * This function should be called before the object that is used/referred in
     * any callback is about to be destroyed. There is always a small chance that
     * there might be an asynchronous visitor that is able to obtain shared
     * pointer reference to this file and try to call any callback.
     */
    void disable();

private:
    FileOps m_ops;

    // Allow directory to call File constructor
    friend class Directory;
    // Can be created only from a directory. Must be always created as a shared_ptr.
    File(const std::shared_ptr<Node>& parent, std::string_view name, FileOps ops);
};

} // namespace ipxp::Telemetry
