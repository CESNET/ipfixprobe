/**
 * @file
 * @author Lukas Hutak <lukas.hutak@hotmail.com>
 * @brief Telemetry directory
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <map>
#include <vector>

#include "file.hpp"
#include "node.hpp"

namespace ipxp::Telemetry {

/**
 * @brief Directory entry.
 *
 * Directory might be empty or it can contain one or more telemetry files and/or directories.
 * Each directory entry has its unique name.
 */
class Directory : public Node {
public:
    ~Directory() override = default;

    Directory(const Directory& other) = delete;
    Directory& operator=(const Directory& other) = delete;
    Directory(Directory&& other) = delete;
    Directory& operator=(Directory&& other) = delete;

    /**
     * @brief Construct an empty root directory.
     */
    [[nodiscard]] static std::shared_ptr<Directory> create();

    /**
     * @brief Add/Get a subdirectory with the given @p name.
     *
     * If the subdirectory with the given name already exists, it will be returned.
     * Otherwise a new empty subdirectory will be created. If a file with the same name
     * already exists, the subdirectory cannot be created.
     *
     * @note
     *   The directory only holds a weak pointer to the subdirectory, so if the returned
     *   pointer ceases to exist, the subdirectory will be removed and it can be replaces
     *   with a new one.
     * @throw NodeException if there is already a file with the same name.
     */
    [[nodiscard]] std::shared_ptr<Directory> addDir(std::string_view name);

    /**
     * @brief Add a new file with the given @p name and @p ops I/O operations.
     *
     * @note
     *   The directory only holds a weak pointer to the file, so if the returned pointer
     *   ceases to exist, the entry will be removed and it can be replaces with a new one.
     * @throw NodeException if there is already a file or directory with the same name.
     */
    [[nodiscard]] std::shared_ptr<File> addFile(std::string_view name, FileOps ops);

    /**
     * @brief List all available entries of the directory.
     * @return All available entries.
     */
    std::vector<std::string> listEntries();

    /**
     * @brief Get an entry with a given @p name.
     *
     * Since this function is usually called from an asynchronous visitor, there is a small
     * chance that an entry with a name obtained by listEntries() cease to exits before this
     * function is called. In other words, the visitor must assume that the function might
     * not be able to get the pointer to the entry.
     *
     * @param name Name of the entry to get.
     * @return Pointer or nullptr (i.e. not found or it doesn't exist anymore).
     */
    [[nodiscard]] std::shared_ptr<Node> getEntry(std::string_view name);

private:
    std::map<std::string, std::weak_ptr<Node>> m_entries;

    // Class must be always created as a shared_ptr.
    Directory() = default;
    Directory(const std::shared_ptr<Node>& parent, std::string_view name);

    std::shared_ptr<Node> getEntryLocked(std::string_view name);
    void addEntryLocked(const std::shared_ptr<Node>& node);

    [[noreturn]] void throwEntryAlreadyExists(std::string_view name);
};

} // namespace ipxp::Telemetry
