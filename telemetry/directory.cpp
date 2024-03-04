/**
 * @file
 * @author Lukas Hutak <lukas.hutak@hotmail.com>
 * @brief Telemetry directory
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "directory.hpp"

namespace ipxp::Telemetry {

Directory::Directory(const std::shared_ptr<Node>& parent, std::string_view name)
    : Node(parent, name)
{
    /*
     * Note: The directory can NOT be added to the parent as an entry here, since
     * this object hasn't been fully initialized yet and shared_from_this()
     * doesn't work in constructors.
     */
}

std::shared_ptr<Directory> Directory::create()
{
    return std::shared_ptr<Directory>(new Directory());
}

std::shared_ptr<Directory> Directory::addDir(std::string_view name)
{
    std::lock_guard lock(getMutex());
    std::shared_ptr<Node> entry = getEntryLocked(name);

    if (entry != nullptr) {
        // Check if the entry also represents a directory
        auto dir = std::dynamic_pointer_cast<Directory>(entry);
        if (dir != nullptr) {
            return dir;
        }

        throwEntryAlreadyExists(name);
    }

    auto newDir = std::shared_ptr<Directory>(new Directory(shared_from_this(), name));
    addEntryLocked(newDir);
    return newDir;
}

std::shared_ptr<File> Directory::addFile(std::string_view name, FileOps ops)
{
    std::lock_guard lock(getMutex());
    std::shared_ptr<Node> entry = getEntryLocked(name);

    if (entry != nullptr) {
        throwEntryAlreadyExists(name);
    }

    auto newFile = std::shared_ptr<File>(new File(shared_from_this(), name, std::move(ops)));
    addEntryLocked(newFile);
    return newFile;
}

std::vector<std::string> Directory::listEntries()
{
    std::vector<std::string> result;
    std::lock_guard lock(getMutex());

    auto iter = m_entries.begin();

    while (iter != m_entries.end()) {
        auto& [name, ref] = *iter;

        // Remove expired entries
        if (ref.expired()) {
            iter = m_entries.erase(iter);
            continue;
        }

        result.emplace_back(name);
        iter++;
    }

    return result;
}

std::shared_ptr<Node> Directory::getEntry(std::string_view name)
{
    std::lock_guard lock(getMutex());
    return getEntryLocked(name);
}

std::shared_ptr<Node> Directory::getEntryLocked(std::string_view name)
{
    auto iter = m_entries.find(std::string(name));
    if (iter == m_entries.end()) {
        return nullptr;
    }

    auto ref = iter->second;
    return ref.lock();
}

void Directory::addEntryLocked(const std::shared_ptr<Node>& node)
{
    const std::string& name = node->getName();

    if (auto iter = m_entries.find(name); iter != m_entries.end()) {
        // Entry already exists but it might be already destroyed
        auto& entryRef = iter->second;

        if (!entryRef.expired()) {
            throwEntryAlreadyExists(name);
        }

        m_entries.erase(iter);
    }

    m_entries.emplace(name, node);
}

void Directory::throwEntryAlreadyExists(std::string_view name)
{
    std::string err;

    err = "Directory('" + getFullPath() + "'): ";
    err += "unable to add entry '" + std::string(name) + "' as it already exists";

    throw NodeException(err);
}

} // namespace ipxp::Telemetry
